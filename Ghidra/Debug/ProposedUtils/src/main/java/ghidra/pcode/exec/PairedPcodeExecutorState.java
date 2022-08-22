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

import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;

/**
 * A paired executor state
 * 
 * <p>
 * This composes a delegate state and piece "left" and "write" creating a single state which instead
 * stores pairs of values, where the left component has the value type of the left state, and the
 * right component has the value type of the right state. Note that both states are addressed using
 * only the left "control" component. Otherwise, every operation on this state is decomposed into
 * operations upon the delegate states, and the final result composed from the results of those
 * operations.
 * 
 * <p>
 * Where a response cannot be composed of both states, the paired state defers to the left. In this
 * way, the left state controls the machine, while the right is computed in tandem. The right never
 * directly controls the machine
 * 
 * <p>
 * See {@link PairedPcodeExecutorStatePiece} regarding the composition of three or more pieces.
 * 
 * @param <L> the type of values for the "left" state
 * @param <R> the type of values for the "right" state
 */
public class PairedPcodeExecutorState<L, R> implements PcodeExecutorState<Pair<L, R>> {
	private final PairedPcodeExecutorStatePiece<L, L, R> piece;
	private final PcodeArithmetic<Pair<L, R>> arithmetic;

	public PairedPcodeExecutorState(PairedPcodeExecutorStatePiece<L, L, R> piece) {
		this.piece = piece;
		this.arithmetic = piece.getArithmetic();
	}

	/**
	 * Compose a paired state from the given left and right states
	 * 
	 * @param left the state backing the left side of paired values ("control")
	 * @param right the state backing the right side of paired values ("auxiliary")
	 */
	public PairedPcodeExecutorState(PcodeExecutorState<L> left,
			PcodeExecutorStatePiece<L, R> right, PcodeArithmetic<Pair<L, R>> arithmetic) {
		this.piece =
			new PairedPcodeExecutorStatePiece<>(left, right, left.getArithmetic(), arithmetic);
		this.arithmetic = arithmetic;
	}

	public PairedPcodeExecutorState(PcodeExecutorState<L> left,
			PcodeExecutorStatePiece<L, R> right) {
		this(left, right, new PairedPcodeArithmetic<>(left.getArithmetic(), right.getArithmetic()));
	}

	@Override
	public PcodeArithmetic<Pair<L, R>> getArithmetic() {
		return arithmetic;
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		return piece.getConcreteBuffer(address, purpose);
	}

	/**
	 * Get the delegate backing the left side of paired values
	 * 
	 * @return the left state
	 */
	public PcodeExecutorStatePiece<L, L> getLeft() {
		return piece.getLeft();
	}

	/**
	 * Get the delegate backing the right side of paired values
	 * 
	 * @return the right state
	 */
	public PcodeExecutorStatePiece<L, R> getRight() {
		return piece.getRight();
	}

	@Override
	public void setVar(AddressSpace space, Pair<L, R> offset, int size, boolean quantize,
			Pair<L, R> val) {
		piece.setVar(space, offset.getLeft(), size, quantize, val);
	}

	@Override
	public Pair<L, R> getVar(AddressSpace space, Pair<L, R> offset, int size, boolean quantize) {
		return piece.getVar(space, offset.getLeft(), size, quantize);
	}
}

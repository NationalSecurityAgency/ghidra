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
 * A paired executor state piece
 * 
 * <p>
 * This composes two delegate pieces "left" and "right" creating a single piece which stores pairs
 * of values, where the left component has the value type of the left piece, and the right component
 * has the value type of the right piece. Both pieces must have the same address type. Every
 * operation on this piece is decomposed into operations upon the delegate pieces, and the final
 * result composed from the results of those operations.
 * 
 * <p>
 * To compose three or more states, first ask if it is really necessary. Second, consider
 * implementing the {@link PcodeExecutorStatePiece} interface directly. Third, use the Church-style
 * triple. In that third case, the implementor must decide which side has the nested tuple. Putting
 * it on the right keeps the concrete piece (conventionally on the left) in the most shallow
 * position, so it can be accessed efficiently. However, putting it on the left (implying it's in
 * the deepest position) keeps the concrete piece near the other pieces to which it's most closely
 * bound. The latter goal is only important when the paired arithmetics mix information between
 * their elements.
 * 
 * @see PairedPcodeExecutorState
 * @param <A> the type of offset, usually the type of a controlling state
 * @param <L> the type of the "left" state
 * @param <R> the type of the "right" state
 */
public class PairedPcodeExecutorStatePiece<A, L, R>
		implements PcodeExecutorStatePiece<A, Pair<L, R>> {

	private final PcodeExecutorStatePiece<A, L> left;
	private final PcodeExecutorStatePiece<A, R> right;
	private final PcodeArithmetic<A> addressArithmetic;
	private final PcodeArithmetic<Pair<L, R>> arithmetic;

	public PairedPcodeExecutorStatePiece(PcodeExecutorStatePiece<A, L> left,
			PcodeExecutorStatePiece<A, R> right, PcodeArithmetic<A> addressArithmetic,
			PcodeArithmetic<Pair<L, R>> arithmetic) {
		this.left = left;
		this.right = right;
		this.addressArithmetic = addressArithmetic;
		this.arithmetic = arithmetic;
	}

	public PairedPcodeExecutorStatePiece(PcodeExecutorStatePiece<A, L> left,
			PcodeExecutorStatePiece<A, R> right) {
		this(left, right, left.getAddressArithmetic(),
			new PairedPcodeArithmetic<>(left.getArithmetic(), right.getArithmetic()));
	}

	@Override
	public PcodeArithmetic<A> getAddressArithmetic() {
		return addressArithmetic;
	}

	@Override
	public PcodeArithmetic<Pair<L, R>> getArithmetic() {
		return arithmetic;
	}

	@Override
	public void setVar(AddressSpace space, A offset, int size, boolean quantize, Pair<L, R> val) {
		left.setVar(space, offset, size, quantize, val.getLeft());
		right.setVar(space, offset, size, quantize, val.getRight());
	}

	@Override
	public Pair<L, R> getVar(AddressSpace space, A offset, int size, boolean quantize) {
		return Pair.of(
			left.getVar(space, offset, size, quantize),
			right.getVar(space, offset, size, quantize));
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		return left.getConcreteBuffer(address, purpose);
	}

	/**
	 * Get the delegate backing the left side of paired values
	 * 
	 * @return the left piece
	 */
	public PcodeExecutorStatePiece<A, L> getLeft() {
		return left;
	}

	/**
	 * Get the delegate backing the right side of paired values
	 * 
	 * @return the right piece
	 */
	public PcodeExecutorStatePiece<A, R> getRight() {
		return right;
	}
}

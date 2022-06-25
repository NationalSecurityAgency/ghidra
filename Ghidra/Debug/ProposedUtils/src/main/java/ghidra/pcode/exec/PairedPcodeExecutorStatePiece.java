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

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;

/**
 * A paired executor state piece
 * 
 * <p>
 * This compose two delegate pieces "left" and "right" creating a single piece which instead stores
 * pairs of values, where the left component has the value type of the left state, and the right
 * component has the value type of the right state. Both pieces must have the same address type.
 * Every operation on this piece is decomposed into operations upon the delegate pieces, and the
 * final result composed from the results of those operations.
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

	public PairedPcodeExecutorStatePiece(PcodeExecutorStatePiece<A, L> left,
			PcodeExecutorStatePiece<A, R> right) {
		this.left = left;
		this.right = right;
	}

	@Override
	public A longToOffset(AddressSpace space, long l) {
		return left.longToOffset(space, l);
	}

	@Override
	public void setVar(AddressSpace space, A offset, int size,
			boolean truncateAddressableUnit, Pair<L, R> val) {
		left.setVar(space, offset, size, truncateAddressableUnit, val.getLeft());
		right.setVar(space, offset, size, truncateAddressableUnit, val.getRight());
	}

	@Override
	public Pair<L, R> getVar(AddressSpace space, A offset, int size,
			boolean truncateAddressableUnit) {
		return new ImmutablePair<>(
			left.getVar(space, offset, size, truncateAddressableUnit),
			right.getVar(space, offset, size, truncateAddressableUnit));
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address) {
		return left.getConcreteBuffer(address);
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

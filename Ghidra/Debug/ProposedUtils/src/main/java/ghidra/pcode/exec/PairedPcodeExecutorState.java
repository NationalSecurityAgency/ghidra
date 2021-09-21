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
 * A paired executor state
 * 
 * <p>
 * Where a response cannot be composed of both states, the paired state defers to the left. In this
 * way, the left state controls the machine, while the right is computed in tandem. The right never
 * directly controls the machine; however, by overriding
 * {@link #getVar(AddressSpace, Object, int, boolean)} and/or
 * {@link #setVar(AddressSpace, Object, int, boolean, Object)}, the right can affect the left and
 * indirectly control the machine.
 * 
 * @param <L> the type of values for the "left" state
 * @param <R> the type of values for the "right" state
 */
public class PairedPcodeExecutorState<L, R>
		extends AbstractOffsetTransformedPcodeExecutorState<Pair<L, R>, L, Pair<L, R>>
		implements PcodeExecutorState<Pair<L, R>> {

	private final PcodeExecutorStatePiece<L, L> left;
	private final PcodeExecutorStatePiece<L, R> right;

	public PairedPcodeExecutorState(PcodeExecutorStatePiece<L, L> left,
			PcodeExecutorStatePiece<L, R> right) {
		super(new PairedPcodeExecutorStatePiece<>(left, right));
		this.left = left;
		this.right = right;
	}

	@Override
	public Pair<L, R> longToOffset(AddressSpace space, long l) {
		return new ImmutablePair<>(left.longToOffset(space, l), null);
	}

	@Override
	protected L transformOffset(Pair<L, R> offset) {
		return offset.getLeft();
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address) {
		return left.getConcreteBuffer(address);
	}

	public PcodeExecutorStatePiece<L, L> getLeft() {
		return left;
	}

	public PcodeExecutorStatePiece<L, R> getRight() {
		return right;
	}
}

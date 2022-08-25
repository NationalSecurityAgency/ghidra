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
package ghidra.pcode.exec.trace;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.exec.PairedPcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;

/**
 * A trace-bound state piece composed of two other trace-bound pieces sharing the same address type
 *
 * @see PairedPcodeExecutorStatePiece
 * @param <A> the type of addresses
 * @param <L> the type of values for the left piece
 * @param <R> the type of values for the right piece
 */
public class PairedTracePcodeExecutorStatePiece<A, L, R>
		extends PairedPcodeExecutorStatePiece<A, L, R>
		implements TracePcodeExecutorStatePiece<A, Pair<L, R>> {

	protected final TracePcodeExecutorStatePiece<A, L> left;
	protected final TracePcodeExecutorStatePiece<A, R> right;

	public PairedTracePcodeExecutorStatePiece(TracePcodeExecutorStatePiece<A, L> left,
			TracePcodeExecutorStatePiece<A, R> right) {
		super(left, right);
		this.left = left;
		this.right = right;
	}

	public PairedTracePcodeExecutorStatePiece(TracePcodeExecutorStatePiece<A, L> left,
			TracePcodeExecutorStatePiece<A, R> right, PcodeArithmetic<A> addressArithmetic,
			PcodeArithmetic<Pair<L, R>> arithmetic) {
		super(left, right, addressArithmetic, arithmetic);
		this.left = left;
		this.right = right;
	}

	@Override
	public void writeDown(Trace trace, long snap, TraceThread thread, int frame) {
		left.writeDown(trace, snap, thread, frame);
		right.writeDown(trace, snap, thread, frame);
	}

	@Override
	public TracePcodeExecutorStatePiece<A, L> getLeft() {
		return left;
	}

	@Override
	public TracePcodeExecutorStatePiece<A, R> getRight() {
		return right;
	}
}

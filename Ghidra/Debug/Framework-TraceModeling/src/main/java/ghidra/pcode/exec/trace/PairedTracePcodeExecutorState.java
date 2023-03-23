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

import ghidra.pcode.exec.PairedPcodeExecutorState;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;

/**
 * A trace-bound state composed of another trace-bound state and a piece
 *
 * @param <L> the type of values for the left state
 * @param <R> the type of values for the right piece
 * @see PairedPcodeExecutorState
 */
public class PairedTracePcodeExecutorState<L, R> extends PairedPcodeExecutorState<L, R>
		implements TracePcodeExecutorState<Pair<L, R>> {

	private final PairedTracePcodeExecutorStatePiece<L, L, R> piece;

	public PairedTracePcodeExecutorState(PairedTracePcodeExecutorStatePiece<L, L, R> piece) {
		super(piece);
		this.piece = piece;
	}

	public PairedTracePcodeExecutorState(TracePcodeExecutorState<L> left,
			TracePcodeExecutorStatePiece<L, R> right) {
		this(new PairedTracePcodeExecutorStatePiece<>(left, right));
	}

	@Override
	public PcodeTraceDataAccess getData() {
		return piece.getData();
	}

	@Override
	public PairedTracePcodeExecutorState<L, R> fork() {
		return new PairedTracePcodeExecutorState<>(piece.fork());
	}

	@Override
	public void writeDown(PcodeTraceDataAccess into) {
		piece.writeDown(into);
	}
}

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

import ghidra.pcode.exec.DefaultPcodeExecutorState;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;

/**
 * An adapter that implements {@link TracePcodeExecutorState} given a
 * {@link TracePcodeExecutorStatePiece} whose address and value types already match
 * 
 * @param <T> the type of values
 */
public class DefaultTracePcodeExecutorState<T> extends DefaultPcodeExecutorState<T>
		implements TracePcodeExecutorState<T> {

	protected final TracePcodeExecutorStatePiece<T, T> piece;

	/**
	 * Wrap a state piece
	 * 
	 * @param piece the piece
	 */
	public DefaultTracePcodeExecutorState(TracePcodeExecutorStatePiece<T, T> piece) {
		super(piece);
		this.piece = piece;
	}

	@Override
	public void writeDown(Trace trace, long snap, TraceThread thread, int frame) {
		piece.writeDown(trace, snap, thread, frame);
	}
}

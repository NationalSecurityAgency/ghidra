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

import java.util.concurrent.CompletableFuture;

import ghidra.app.services.TraceRecorder;
import ghidra.trace.model.thread.TraceThread;

/**
 * A state composing a single {@link TraceRecorderAsyncPcodeExecutorStatePiece}
 */
public class TraceRecorderAsyncPcodeExecutorState
		extends DefaultPcodeExecutorState<CompletableFuture<byte[]>> {
	/**
	 * Create the state
	 * 
	 * @param recorder the recorder for the trace's live target
	 * @param snap the user's current snap
	 * @param thread the user's current thread
	 * @param frame the user's current frame
	 */
	public TraceRecorderAsyncPcodeExecutorState(TraceRecorder recorder, long snap,
			TraceThread thread, int frame) {
		super(new TraceRecorderAsyncPcodeExecutorStatePiece(recorder, snap, thread, frame));
	}
}

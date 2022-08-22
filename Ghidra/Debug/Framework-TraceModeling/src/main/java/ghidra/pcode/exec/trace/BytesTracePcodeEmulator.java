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

import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;

/**
 * An emulator that can read initial state from a trace and record its state back into it
 */
public class BytesTracePcodeEmulator extends PcodeEmulator implements TracePcodeMachine<byte[]> {
	protected final Trace trace;
	protected final long snap;

	/**
	 * Create a trace-bound emulator
	 * 
	 * @param trace the trace
	 * @param snap the snap from which it lazily reads its state
	 */
	public BytesTracePcodeEmulator(Trace trace, long snap) {
		super(trace.getBaseLanguage());
		this.trace = trace;
		this.snap = snap;
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	@Override
	public long getSnap() {
		return snap;
	}

	protected TracePcodeExecutorState<byte[]> newState(TraceThread thread) {
		return new BytesTracePcodeExecutorState(trace, snap, thread, 0);
	}

	@Override
	public TracePcodeExecutorState<byte[]> createSharedState() {
		return newState(null);
	}

	@Override
	public TracePcodeExecutorState<byte[]> createLocalState(PcodeThread<byte[]> thread) {
		return newState(getTraceThread(thread));
	}
}

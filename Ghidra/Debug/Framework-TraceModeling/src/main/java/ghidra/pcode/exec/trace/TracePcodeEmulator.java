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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.AbstractPcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.SleighUseropLibrary;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Trace;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;

/**
 * An emulator that can read initial state from a trace
 */
public class TracePcodeEmulator extends AbstractPcodeEmulator {
	private static SleighLanguage assertSleigh(Language language) {
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException("Emulation requires a sleigh language");
		}
		return (SleighLanguage) language;
	}

	protected final Trace trace;
	protected final long snap;

	public TracePcodeEmulator(Trace trace, long snap, SleighUseropLibrary<byte[]> library) {
		super(assertSleigh(trace.getBaseLanguage()), library);
		this.trace = trace;
		this.snap = snap;
	}

	public TracePcodeEmulator(Trace trace, long snap) {
		this(trace, snap, SleighUseropLibrary.nil());
	}

	@Override
	protected PcodeExecutorState<byte[]> createMemoryState() {
		return new TraceCachedWriteBytesPcodeExecutorState(trace, snap, null, 0);
	}

	@Override
	protected PcodeExecutorState<byte[]> createRegisterState(PcodeThread<byte[]> emuThread) {
		TraceThread traceThread =
			trace.getThreadManager().getLiveThreadByPath(snap, emuThread.getName());
		return new TraceCachedWriteBytesPcodeExecutorState(trace, snap, traceThread, 0);
	}

	/**
	 * Write the accumulated writes into the given trace at the given snap
	 * 
	 * <p>
	 * NOTE: This method requires a transaction to have already been started on the destination
	 * trace. The destination threads must have equal names/paths at the given threadsSnap. When
	 * using scratch space, threadsSnap should be the source snap. If populating a new trace,
	 * threadsSnap should probably be the destination snap.
	 * 
	 * @param trace the trace to modify
	 * @param destSnap the destination snap within the trace
	 * @param threadsSnap the snap at which to find corresponding threads
	 * @param synthesizeStacks true to synthesize the innermost stack frame of each thread
	 */
	public void writeDown(Trace trace, long destSnap, long threadsSnap, boolean synthesizeStacks) {
		TraceCachedWriteBytesPcodeExecutorState ms =
			(TraceCachedWriteBytesPcodeExecutorState) getMemoryState();
		ms.writeCacheDown(trace, destSnap, null, 0);
		TraceThreadManager threadManager = trace.getThreadManager();
		for (PcodeThread<byte[]> emuThread : threads.values()) {
			TraceCachedWriteBytesPcodeExecutorState rs =
				(TraceCachedWriteBytesPcodeExecutorState) emuThread.getState().getRegisterState();
			TraceThread traceThread = threadManager.getLiveThreadByPath(
				threadsSnap, emuThread.getName());
			if (traceThread == null) {
				throw new IllegalArgumentException(
					"Given trace does not have thread with name/path '" + emuThread.getName() +
						"' at snap " + destSnap);
			}
			rs.writeCacheDown(trace, destSnap, traceThread, 0);
			if (synthesizeStacks) {
				TraceStack stack = trace.getStackManager().getStack(traceThread, destSnap, true);
				stack.getFrame(0, true).setProgramCounter(emuThread.getCounter());
			}
		}
	}
}

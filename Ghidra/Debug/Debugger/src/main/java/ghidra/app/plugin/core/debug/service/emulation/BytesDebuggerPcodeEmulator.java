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
package ghidra.app.plugin.core.debug.service.emulation;

import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emu.*;
import ghidra.pcode.exec.trace.BytesTracePcodeEmulator;
import ghidra.pcode.exec.trace.TracePcodeExecutorState;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;

/**
 * A trace emulator that knows how to read target memory when necessary
 * 
 * <p>
 * This is the default emulator used by the Debugger UI to perform interpolation and extrapolation.
 * For standalone scripting, consider using {@link BytesTracePcodeEmulator} or {@link PcodeEmulator}
 * instead. The former readily reads and records its state to traces, while the latter is the
 * simplest use case. See scripts ending in {@code EmuExampleScript} for example uses.
 * 
 * <p>
 * This emulator must always be run in its own thread, or at least a thread that can never lock the
 * UI. It blocks on target reads so that execution can proceed synchronously. Probably the most
 * suitable option is to use a background task.
 */
public class BytesDebuggerPcodeEmulator extends BytesTracePcodeEmulator
		implements DebuggerPcodeMachine<byte[]> {
	protected final PluginTool tool;
	protected final TraceRecorder recorder;

	/**
	 * Create the emulator
	 * 
	 * @param tool the tool creating the emulator
	 * @param trace the trace from which the emulator loads state
	 * @param snap the snap from which the emulator loads state
	 * @param recorder if applicable, the recorder for the trace's live target
	 */
	public BytesDebuggerPcodeEmulator(PluginTool tool, Trace trace, long snap,
			TraceRecorder recorder) {
		super(trace, snap);
		this.tool = tool;
		this.recorder = recorder;
	}

	@Override
	public PluginTool getTool() {
		return tool;
	}

	@Override
	public TraceRecorder getRecorder() {
		return recorder;
	}

	@Override
	protected BytesPcodeThread createThread(String name) {
		BytesPcodeThread thread = super.createThread(name);
		initializeThreadContext(thread);
		return thread;
	}

	@Override
	public TracePcodeExecutorState<byte[]> createSharedState() {
		return new ReadsTargetMemoryPcodeExecutorState(tool, trace, snap, null, 0, recorder);
	}

	@Override
	public TracePcodeExecutorState<byte[]> createLocalState(PcodeThread<byte[]> emuThread) {
		TraceThread traceThread =
			trace.getThreadManager().getLiveThreadByPath(snap, emuThread.getName());
		return new ReadsTargetRegistersPcodeExecutorState(tool, trace, snap, traceThread, 0,
			recorder);
	}
}

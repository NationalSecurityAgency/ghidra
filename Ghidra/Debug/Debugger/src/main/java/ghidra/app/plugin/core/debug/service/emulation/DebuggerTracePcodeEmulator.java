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
import ghidra.pcode.emu.BytesPcodeThread;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.trace.TracePcodeEmulator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;

/**
 * A trace emulator that knows how to read target memory when necessary
 * 
 * <p>
 * This emulator must always be run in its own thread, or at least a thread that can never lock the
 * UI. It blocks on target reads so that execution can proceed synchronously. Probably the most
 * suitable option is to use a background task.
 */
public class DebuggerTracePcodeEmulator extends TracePcodeEmulator {
	protected final PluginTool tool;
	protected final TraceRecorder recorder;

	public DebuggerTracePcodeEmulator(PluginTool tool, Trace trace, long snap,
			TraceRecorder recorder) {
		super(trace, snap);
		this.tool = tool;
		this.recorder = recorder;
	}

	protected boolean isRegisterKnown(String threadName, Register register) {
		TraceThread thread = trace.getThreadManager().getLiveThreadByPath(snap, threadName);
		TraceMemoryRegisterSpace space =
			trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
		if (space == null) {
			return false;
		}
		return space.getState(snap, register) == TraceMemoryState.KNOWN;
	}

	@Override
	protected BytesPcodeThread createThread(String name) {
		BytesPcodeThread thread = super.createThread(name);
		Register contextreg = language.getContextBaseRegister();
		if (contextreg != null && !isRegisterKnown(name, contextreg)) {
			RegisterValue context = trace.getRegisterContextManager()
					.getValueWithDefault(language, contextreg, snap, thread.getCounter());
			thread.overrideContext(context);
		}
		return thread;
	}

	@Override
	protected PcodeExecutorState<byte[]> createMemoryState() {
		return new ReadsTargetMemoryPcodeExecutorState(tool, trace, snap, null, 0,
			recorder);
	}

	@Override
	protected PcodeExecutorState<byte[]> createRegisterState(PcodeThread<byte[]> emuThread) {
		TraceThread traceThread =
			trace.getThreadManager().getLiveThreadByPath(snap, emuThread.getName());
		return new ReadsTargetRegistersPcodeExecutorState(tool, trace, snap, traceThread, 0,
			recorder);
	}
}

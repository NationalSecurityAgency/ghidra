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

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.service.emulation.*;
import ghidra.app.plugin.core.debug.service.emulation.data.DefaultPcodeDebuggerAccess;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emu.ThreadPcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;

/**
 * Utilities for evaluating or executing Sleigh/p-code in the Debugger
 */
public enum DebuggerPcodeUtils {
	;

	/**
	 * Get a p-code executor state for the given coordinates
	 * 
	 * <p>
	 * If a thread is included, the executor state will have access to both the memory and registers
	 * in the context of that thread. Otherwise, only memory access is permitted.
	 * 
	 * @param tool the plugin tool. TODO: This shouldn't be required
	 * @param coordinates the coordinates
	 * @return the state
	 */
	public static PcodeExecutorState<byte[]> executorStateForCoordinates(PluginTool tool,
			DebuggerCoordinates coordinates) {
		// TODO: Make platform part of coordinates
		Trace trace = coordinates.getTrace();
		if (trace == null) {
			throw new IllegalArgumentException("Coordinates have no trace");
		}
		TracePlatform platform = coordinates.getPlatform();
		Language language = platform.getLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException(
				"Given trace or platform does not use a Sleigh language");
		}
		DefaultPcodeDebuggerAccess access = new DefaultPcodeDebuggerAccess(tool,
			coordinates.getRecorder(), platform, coordinates.getSnap());
		PcodeExecutorState<byte[]> shared =
			new RWTargetMemoryPcodeExecutorState(access.getDataForSharedState(), Mode.RW);
		if (coordinates.getThread() == null) {
			return shared;
		}
		PcodeExecutorState<byte[]> local = new RWTargetRegistersPcodeExecutorState(
			access.getDataForLocalState(coordinates.getThread(), coordinates.getFrame()), Mode.RW);
		return new ThreadPcodeExecutorState<>(shared, local);
	}

	/**
	 * Get an executor which can be used to evaluate Sleigh expressions at the given coordinates
	 * 
	 * <p>
	 * If a thread is included, the executor will have access to both the memory and registers in
	 * the context of that thread. Otherwise, only memory access is permitted.
	 * 
	 * @param tool the plugin tool. TODO: This shouldn't be required
	 * @param coordinates the coordinates
	 * @return the executor
	 */
	public static PcodeExecutor<byte[]> executorForCoordinates(PluginTool tool,
			DebuggerCoordinates coordinates) {
		PcodeExecutorState<byte[]> state = executorStateForCoordinates(tool, coordinates);

		SleighLanguage slang = (SleighLanguage) state.getLanguage();
		return new PcodeExecutor<>(slang, BytesPcodeArithmetic.forLanguage(slang), state,
			Reason.INSPECT);
	}
}

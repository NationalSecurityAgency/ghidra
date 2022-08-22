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
import ghidra.pcode.exec.trace.DefaultTracePcodeExecutorState;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;

/**
 * A state composing a single {@link ReadsTargetRegistersPcodeExecutorStatePiece}
 */
public class ReadsTargetRegistersPcodeExecutorState extends DefaultTracePcodeExecutorState<byte[]> {
	/**
	 * Create the state
	 * 
	 * @param tool the tool of the emulator
	 * @param trace the trace of the emulator
	 * @param snap the snap of the emulator
	 * @param thread the thread to which the state is assigned
	 * @param frame the frame to which the state is assigned, probably 0
	 * @param recorder the recorder of the emulator
	 */
	public ReadsTargetRegistersPcodeExecutorState(PluginTool tool, Trace trace, long snap,
			TraceThread thread, int frame, TraceRecorder recorder) {
		super(new ReadsTargetRegistersPcodeExecutorStatePiece(tool, trace, snap, thread, frame,
			recorder));
	}
}

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
package ghidra.debug.api.emulation;

import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.trace.data.PcodeTraceAccess;
import ghidra.trace.model.thread.TraceThread;

/**
 * A trace-and-debugger access shim
 * 
 * <p>
 * In addition to the trace "coordinates" encapsulated by {@link PcodeTraceAccess}, this
 * encapsulates the tool controlling a session and the session's target. This permits p-code
 * executor/emulator states to access target data and to access session data, e.g., data from mapped
 * static images. It supports the same method chain pattern as {@link PcodeTraceAccess}, but
 * starting with {@link DefaultPcodeDebuggerAccess}.
 */
public interface PcodeDebuggerAccess extends PcodeTraceAccess {
	@Override
	PcodeDebuggerMemoryAccess getDataForSharedState();

	@Override
	PcodeDebuggerRegistersAccess getDataForLocalState(PcodeThread<?> thread, int frame);

	@Override
	PcodeDebuggerRegistersAccess getDataForLocalState(TraceThread thread, int frame);
}

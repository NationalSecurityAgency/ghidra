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
package ghidra.app.plugin.core.debug.service.emulation.data;

import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.trace.data.AbstractPcodeTraceAccess;
import ghidra.trace.model.guest.TracePlatform;

/**
 * An abstract implementation of {@link PcodeDebuggerAccess}
 *
 * @param <S> the type of shared data-access shims provided
 * @param <L> the type of thread-local data-access shims provided
 */
public abstract class AbstractPcodeDebuggerAccess<S extends PcodeDebuggerMemoryAccess, L extends PcodeDebuggerRegistersAccess>
		extends AbstractPcodeTraceAccess<S, L>
		implements PcodeDebuggerAccess {

	protected final PluginTool tool;
	protected final TraceRecorder recorder;

	/**
	 * Construct a shim
	 * 
	 * @param tool the tool controlling the session
	 * @param recorder the target's recorder
	 * @param platform the associated platform, having the same trace as the recorder
	 * @param snap the associated snap
	 */
	public AbstractPcodeDebuggerAccess(PluginTool tool, TraceRecorder recorder,
			TracePlatform platform, long snap) {
		super(platform, snap);
		this.tool = tool;
		this.recorder = recorder;
	}
}

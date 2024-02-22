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

import ghidra.debug.api.target.Target;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;

/**
 * The default target-and-trace access shim for a session
 */
public class DefaultPcodeDebuggerAccess extends
		AbstractPcodeDebuggerAccess //
		<DefaultPcodeDebuggerMemoryAccess, DefaultPcodeDebuggerRegistersAccess> {

	/**
	 * Construct a shim
	 * 
	 * @param provider the service provider (usually the tool)
	 * @param target the target
	 * @param platform the associated platform, having the same trace as the recorder
	 * @param snap the associated snap
	 */
	public DefaultPcodeDebuggerAccess(ServiceProvider provider, Target target,
			TracePlatform platform, long snap) {
		super(provider, target, platform, snap);
	}

	@Override
	protected DefaultPcodeDebuggerMemoryAccess newDataForSharedState() {
		return new DefaultPcodeDebuggerMemoryAccess(provider, target, platform, snap, viewport);
	}

	@Override
	protected DefaultPcodeDebuggerRegistersAccess newDataForLocalState(TraceThread thread,
			int frame) {
		return new DefaultPcodeDebuggerRegistersAccess(provider, target, platform, snap, thread,
			frame, viewport);
	}
}

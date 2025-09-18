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
import ghidra.pcode.exec.trace.data.DefaultPcodeTraceAccess;
import ghidra.pcode.exec.trace.data.PcodeTraceAccess;
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

	/**
	 * Construct a shim
	 * 
	 * @param provider the service provider (usually the tool)
	 * @param target the target
	 * @param platform the associated platform, having the same trace as the recorder
	 * @param snap the associated snap
	 * @param threadsSnap the snap to use when finding associated threads between trace and emulator
	 */
	public DefaultPcodeDebuggerAccess(ServiceProvider provider, Target target,
			TracePlatform platform, long snap, long threadsSnap) {
		super(provider, target, platform, snap, threadsSnap);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote This does <em>not</em> return a Debugger access shim, but a Trace one, since we
	 *           never expect a delayed write to affect the target.
	 */
	@Override
	public PcodeTraceAccess deriveForWrite(long snap) {
		return new DefaultPcodeTraceAccess(platform, snap, threadsSnap);
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

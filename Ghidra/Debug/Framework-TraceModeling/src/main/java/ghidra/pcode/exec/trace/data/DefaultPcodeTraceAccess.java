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
package ghidra.pcode.exec.trace.data;

import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;

/**
 * The default trace access shim for a session
 */
public class DefaultPcodeTraceAccess extends AbstractPcodeTraceAccess //
<DefaultPcodeTraceMemoryAccess, DefaultPcodeTraceRegistersAccess> {

	/**
	 * Construct a shim
	 * 
	 * @param platform the associated platform
	 * @param snap the associated snap
	 * @param threadsSnap the snap to use when finding associated threads between trace and emulator
	 */
	public DefaultPcodeTraceAccess(TracePlatform platform, long snap, long threadsSnap) {
		super(platform, snap, threadsSnap);
	}

	/**
	 * Construct a shim
	 * 
	 * @param platform the associated platform
	 * @param snap the associated snap
	 */
	public DefaultPcodeTraceAccess(TracePlatform platform, long snap) {
		super(platform, snap);
	}

	@Override
	protected DefaultPcodeTraceMemoryAccess newDataForSharedState() {
		return new DefaultPcodeTraceMemoryAccess(platform, snap, viewport);
	}

	@Override
	protected DefaultPcodeTraceRegistersAccess newDataForLocalState(TraceThread thread, int frame) {
		return new DefaultPcodeTraceRegistersAccess(platform, snap, thread, frame, viewport);
	}
}

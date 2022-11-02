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

import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;

/**
 * A data-access shim for a trace and the debugger
 * 
 * <p>
 * This shim, in addition to the trace, can also access its associated target, as well as session
 * information maintained by the Debugger tool.
 */
public interface PcodeDebuggerDataAccess extends PcodeTraceDataAccess {
	/**
	 * Check if the associated trace represents a live session
	 * 
	 * <p>
	 * The session is live if it's trace has a recorder and the source snapshot matches the
	 * recorder's destination snapshot.
	 * 
	 * @return true if live, false otherwise
	 */
	boolean isLive();
}

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
package agent.lldb.lldb;

import SWIG.SBEvent;

/**
 * Information about a breakpoint (or watchpoint).
 */
public class DebugBreakpointInfo {

	public SBEvent event;
	public Object pt;
	public String id;

	public DebugBreakpointInfo(SBEvent event, Object pt) {
		this.event = event;
		this.pt = pt;
		this.id = DebugClient.getId(pt);
	}

	@Override
	public String toString() {
		return id;
	}
}

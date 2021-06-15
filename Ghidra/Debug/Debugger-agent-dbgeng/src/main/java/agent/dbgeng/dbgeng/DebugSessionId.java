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
package agent.dbgeng.dbgeng;

/**
 * The <em>engine</em> ID assigned to a debugged process.
 * 
 * Note: This is not the same as the "PID." {@code dbgeng.dll} calls that the <em>system</em> ID of
 * the process.
 * 
 * This is essentially just a boxed integer, but having an explicit data type prevents confusion
 * with other integral values. In particular, this prevents confusion of engine PIDs with system
 * PIDs.
 */
public class DebugSessionId implements Comparable<DebugSessionId> {
	public final int id;

	public DebugSessionId(int id) {
		this.id = id;
	}

	@Override
	public int hashCode() {
		return Integer.hashCode(id);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof DebugSessionId)) {
			return false;
		}
		DebugSessionId that = (DebugSessionId) obj;
		if (this.id != that.id) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(DebugSessionId that) {
		return Integer.compare(this.id, that.id);
	}

	@Override
	public String toString() {
		return "<dbgeng.dll Engine SYSID " + id + ">";
	}
}

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
 * The <em>engine</em> ID assigned to a debugged thread.
 * 
 * Note: This is not the same as the "TID." {@code dbgeng.dll} calls that the <em>system</em> ID of
 * the thread.
 * 
 * This is essentially just a boxed integer, but having an explicit data type prevents confusion
 * with other integral values. In particular, this prevents confusion of engine TIDs with system
 * TIDs.
 */
public class DebugThreadId implements Comparable<DebugThreadId> {
	public final int id;

	public DebugThreadId(int id) {
		this.id = id;
	}

	@Override
	public int hashCode() {
		return Integer.hashCode(id);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof DebugThreadId)) {
			return false;
		}
		DebugThreadId that = (DebugThreadId) obj;
		if (this.id != that.id) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(DebugThreadId that) {
		return Integer.compare(this.id, that.id);
	}

	@Override
	public String toString() {
		return "<dbgeng.dll Engine TID " + id + ">";
	}
}

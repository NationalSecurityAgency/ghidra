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

/**
 * The ID of a debug server.
 * 
 * Each server to which a client is connected is assigned a server ID. The local server, to which
 * every client is connected by default, has the ID 0. This is essentially just a boxed integer, but
 * having an explicit data type prevents confusion with other integral values.
 */
public class DebugServerId implements Comparable<DebugServerId> {
	public final long id;

	public DebugServerId(long id) {
		this.id = id;
	}

	@Override
	public int hashCode() {
		return Long.hashCode(id);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof DebugServerId)) {
			return false;
		}
		DebugServerId that = (DebugServerId) obj;
		if (this.id != that.id) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(DebugServerId that) {
		return Long.compare(this.id, that.id);
	}

	@Override
	public String toString() {
		return "<LLDB Server ID " + id + ">";
	}
}

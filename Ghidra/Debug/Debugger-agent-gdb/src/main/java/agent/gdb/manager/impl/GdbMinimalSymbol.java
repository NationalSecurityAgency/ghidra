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
package agent.gdb.manager.impl;

public class GdbMinimalSymbol {
	protected final long index;
	protected final String type;
	protected final String name;
	protected final long address;

	public GdbMinimalSymbol(long index, String type, String name, long address) {
		this.index = index;
		this.type = type;
		this.name = name;
		this.address = address;
	}

	public long getIndex() {
		return index;
	}

	public String getType() {
		// TODO: Interpret these types
		// Observed: t, T, D, S
		return type;
	}

	public String getName() {
		return name;
	}

	public long getAddress() {
		return address;
	}
}

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
package agent.dbgeng.manager.impl;

public class DbgMinimalSymbol {
	protected final long index;
	protected final int typeId;
	protected final String name;
	protected final long address;
	protected final long size;
	private final int tag;
	private final long moduleBase;

	public DbgMinimalSymbol(long index, int typeId, String name, long address, long size, int tag,
			long moduleBase) {
		this.index = index;
		this.typeId = typeId;
		this.name = name;
		this.address = address;
		this.size = size;
		this.tag = tag;
		this.moduleBase = moduleBase;
	}

	public long getIndex() {
		return index;
	}

	public int getTypeId() {
		return typeId;
	}

	public String getName() {
		return name;
	}

	public long getAddress() {
		return address;
	}

	public long getSize() {
		return size;
	}

	public int getTag() {
		return tag;
	}

	public long getModuleBase() {
		return moduleBase;
	}
}

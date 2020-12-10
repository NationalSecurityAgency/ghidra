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
 * Data copied from a {@code DEBUG_SYMBOL_ENTRY} as defined in {@code dbgeng.h}.
 * 
 * TODO: Some enums, flags, etc., to help interpret some of the fields.
 */
public class DebugSymbolEntry {
	public final long moduleBase;
	public final long offset;
	public final long symbolId;
	public final long size;
	public final int flags;
	public final int typeId;
	public final String name;
	public final int tag;

	public DebugSymbolEntry(long moduleBase, long offset, long symbolId, long size, int flags,
			int typeId, String name, int tag) {
		this.moduleBase = moduleBase;
		this.offset = offset;
		this.symbolId = symbolId;
		this.size = size;
		this.flags = flags;
		this.typeId = typeId;
		this.name = name;
		this.tag = tag;
	}

	@Override
	public String toString() {
		return String.format("<DebugSymbolEntry %016x:%016x\n" + //
			"  offset=%016xh,\n" + //
			"  size=%xh,\n" + //		
			"  flags=%xh,\n" + //
			"  typeId=%xh,\n" + //
			"  name='%s',\n" + //
			"  tag=%xh>", //
			moduleBase, symbolId, offset, size, flags, typeId, name, tag);
	}
}

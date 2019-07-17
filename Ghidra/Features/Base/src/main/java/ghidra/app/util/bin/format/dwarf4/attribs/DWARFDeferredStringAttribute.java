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
package ghidra.app.util.bin.format.dwarf4.attribs;

import ghidra.app.util.bin.format.dwarf4.next.StringTable;

import java.io.IOException;

/**
 * DWARF string attribute, where getting the value from the string table is deferred
 * until requested for the first time.
 */
public class DWARFDeferredStringAttribute extends DWARFStringAttribute {
	private long offset;

	public DWARFDeferredStringAttribute(long offset) {
		super(null);
		this.offset = offset;
	}

	@Override
	public String getValue(StringTable stringTable) {
		if (value == null) {
			try {
				value = stringTable.getStringAtOffset(offset);
			}
			catch (IOException e) {
				return null;
			}
		}
		return value;
	}

	@Override
	public String toString() {
		return "DWARFDeferredStringAttribute [ offset=" + offset + ", value=" + value + "]";
	}

}

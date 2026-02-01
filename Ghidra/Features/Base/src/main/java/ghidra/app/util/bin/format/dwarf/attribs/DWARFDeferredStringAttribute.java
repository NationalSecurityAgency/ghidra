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
package ghidra.app.util.bin.format.dwarf.attribs;

import java.io.IOException;

import ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit;
import ghidra.util.Msg;

/**
 * DWARF string attribute, where getting the value from the string table is deferred
 * until requested for the first time.
 */
public class DWARFDeferredStringAttribute extends DWARFStringAttribute {
	private long offset;

	public DWARFDeferredStringAttribute(long offset, DWARFAttributeDef<?> def) {
		super(null, def);
		this.offset = offset;
	}

	@Override
	public String getValue(DWARFCompilationUnit cu) {
		if (value == null) {
			try {
				value = cu.getProgram().getString(getAttributeForm(), offset, cu);
			}
			catch (IOException e) {
				Msg.error(this, "error getting string value", e);
				return null;
			}
		}
		return value;
	}

	public long getOffset() {
		return offset;
	}

	@Override
	public String toString(DWARFCompilationUnit cu) {
		String str = value == null && cu != null ? getValue(cu) : value;
		str = str != null ? "\"%s\"".formatted(value) : "-missing-";
		return "%s : %s = %s (offset 0x%x)".formatted(getAttributeName(), getAttributeForm(), str,
			offset);
	}

	@Override
	public String toString() {
		return toString(null);
	}
}

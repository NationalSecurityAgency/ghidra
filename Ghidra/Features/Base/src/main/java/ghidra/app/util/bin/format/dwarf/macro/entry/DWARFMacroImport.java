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
package ghidra.app.util.bin.format.dwarf.macro.entry;

import java.io.IOException;

import ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFNumericAttribute;
import ghidra.app.util.bin.format.dwarf.macro.DWARFMacroHeader;

/**
 * Represents the inclusion of macro entries from another macro header. 
 */
public class DWARFMacroImport extends DWARFMacroInfoEntry {

	public DWARFMacroImport(DWARFMacroInfoEntry other) {
		super(other);
	}

	public long getOffset() throws IOException {
		return getOperand(0, DWARFNumericAttribute.class).getUnsignedValue();
	}

	public DWARFMacroHeader getImportedMacroHeader() throws IOException {
		long offset = getOffset();
		DWARFCompilationUnit cu = macroHeader.getCompilationUnit();
		return cu.getProgram().getMacroHeader(offset, cu);
	}

}

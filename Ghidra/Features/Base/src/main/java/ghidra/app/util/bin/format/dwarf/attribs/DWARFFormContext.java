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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.*;

/**
 * Context given to the {@link DWARFForm#readValue(DWARFFormContext)} method to enable it to
 * create {@link DWARFAttributeValue}s.
 * 
 * @param reader {@link BinaryReader} 
 * @param compUnit {@link DWARFCompilationUnit}
 * @param def {@link DWARFAttributeDef}
 */
public record DWARFFormContext(BinaryReader reader, DWARFCompilationUnit compUnit,
		DWARFAttributeDef<?> def) {

	DWARFProgram dprog() {
		return compUnit.getProgram();
	}

	int dwarfIntSize() {
		return compUnit.getIntSize();
	}
}

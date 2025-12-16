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
import ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit;
import ghidra.app.util.bin.format.dwarf.DWARFProgram;

/**
 * Context given to the {@link DWARFForm#readValue(DWARFFormContext)} method to enable it to
 * create {@link DWARFAttributeValue}s.
 * 
 * @param reader {@link BinaryReader} 
 * @param compUnit {@link DWARFCompilationUnit}
 * @param def {@link DWARFAttributeDef}
 * @param dwarfIntSize size of dwarf serialization ints, either 4 (32 bit dwarf) or 
 * 	8 (64 bit dwarf).  Can be different from compUnit's intSize if this context is being used
 * 	to read values from a non-".debuginfo" section that has unit headers that specify an
 * 	independent intSize. 
 */
public record DWARFFormContext(BinaryReader reader, DWARFCompilationUnit compUnit,
		DWARFAttributeDef<?> def, int dwarfIntSize) {

	/**
	 * Creates a new DWARFFormContext, using the compUnit's int size
	 * 
	 * @param reader stream that will be used to read the dwarf form value
	 * @param compUnit {@link DWARFCompilationUnit} that contains the value
	 * @param def identity info about the attribute being read
	 */
	public DWARFFormContext(BinaryReader reader, DWARFCompilationUnit compUnit,
			DWARFAttributeDef<?> def) {
		this(reader, compUnit, def, compUnit.getIntSize());
	}

	DWARFProgram dprog() {
		return compUnit.getProgram();
	}
}

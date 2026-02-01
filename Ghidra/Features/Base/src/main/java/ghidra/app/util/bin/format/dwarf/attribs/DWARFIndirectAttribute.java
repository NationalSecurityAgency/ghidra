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
import ghidra.app.util.bin.format.dwarf.DWARFProgram;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionNames;

/**
 *  DWARF numeric attribute value that is an index into a lookup table
 */
public class DWARFIndirectAttribute extends DWARFNumericAttribute {

	public DWARFIndirectAttribute(long index, DWARFAttributeDef<?> def) {
		super(index, def);
	}

	public int getIndex() throws IOException {
		return getUnsignedIntExact();
	}

	@Override
	public String toString(DWARFCompilationUnit cu) {
		try {
			DWARFProgram prog = cu.getProgram();
			int index = getIndex();
			long offset = prog.getOffsetOfIndexedElement(getAttributeForm(), index, cu);
			if (getAttributeForm().isClass(DWARFAttributeClass.address)) {
				return "%s : %s, addr v%d 0x%x (idx %d)".formatted(getAttributeName(),
					getAttributeForm(), cu.getDWARFVersion(), offset, index);
			}
			else if (getAttributeForm().isClass(DWARFAttributeClass.rnglist)) {
				return toElementLocationString("rnglist", DWARFSectionNames.DEBUG_RNGLISTS, index,
					offset, cu.getDWARFVersion());
			}
			else if (getAttributeForm().isClass(DWARFAttributeClass.loclist)) {
				return toElementLocationString("loclist", DWARFSectionNames.DEBUG_LOCLISTS, index,
					offset, cu.getDWARFVersion());
			}
			else if (getAttributeForm().isClass(DWARFAttributeClass.string)) {
				return toElementLocationString("string", DWARFSectionNames.DEBUG_LOCLISTS, index,
					offset, cu.getDWARFVersion());
			}
		}
		catch (IOException e) {
			// fall thru to default
		}
		return super.toString(cu);
	}

	@Override
	public String toString() {
		long index = getUnsignedValue();
		return "%s : %s, index/offset %d [0x%x]".formatted(getAttributeName(), getAttributeForm(),
			index, index);
	}
}

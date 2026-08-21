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

import static ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionId.*;

import java.io.IOException;

import ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit;

/**
 *  DWARF numeric attribute value that is an index into a lookup table
 */
public class DWARFIndirectAttribute extends DWARFNumericAttribute {

	public DWARFIndirectAttribute(long index) {
		super(index);
	}

	public int getIndex() throws IOException {
		return getUnsignedIntExact();
	}

	@Override
	public String getValueString(DWARFCompilationUnit cu, DWARFAttributeDef<?> def) {
		DWARFForm form = def.getAttributeForm();
		try {
			int index = getIndex();
			long offset = cu.getDIEContainer().getOffsetOfIndexedElement(form, index, cu);
			if (form.isClass(DWARFAttributeClass.address)) {
				return "addr v%d 0x%x (idx %d)".formatted(cu.getDWARFVersion(), offset, index);
			}
			else if (form.isClass(DWARFAttributeClass.rnglist)) {
				return toElementLocationString("rnglist", DEBUG_RNGLISTS.getSectionName(), index,
					offset, cu.getDWARFVersion());
			}
			else if (form.isClass(DWARFAttributeClass.loclist)) {
				return toElementLocationString("loclist", DEBUG_LOCLISTS.getSectionName(), index,
					offset, cu.getDWARFVersion());
			}
			else if (form.isClass(DWARFAttributeClass.string)) {
				return toElementLocationString("string", "string_list_???", index,
					offset, cu.getDWARFVersion());
			}
		}
		catch (IOException e) {
			// fall thru to default
		}
		return super.getValueString(cu, def);
	}

	@Override
	public String toString() {
		return "indirect " + super.toString();
	}
}

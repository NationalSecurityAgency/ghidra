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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.DWARFCompilationUnit;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFForm;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 * Test helper that injects errors when reading DWARF attributes from a stream.
 * <p>
 * Used with real DWARF binaries to inject changes / errors at specific locations
 * in the file that the tester determined was an important point.
 */
public class DWARFAttributeFactoryFlaky extends DWARFAttributeFactory {

	private int counter;
	private Set<Long> offsets = new HashSet<>();

	public DWARFAttributeFactoryFlaky(DWARFProgram prog) {
		super(prog);
	}

	public DWARFAttributeFactoryFlaky addOffset(long offset) {
		offsets.add(offset);
		return this;
	}

	public DWARFAttributeValue read(BinaryReader reader, DWARFCompilationUnit unit, DWARFForm form)
			throws IOException {
		counter++;

		long offset = reader.getPointerIndex();
		DWARFAttributeValue result = super.read(reader, unit, form);

		if (shouldError(offset, result, form)) {
			result = injectError(offset, result, form);
		}

		return result;
	}

	private boolean shouldError(long offset, DWARFAttributeValue attribute, DWARFForm form) {
		return offsets.contains(offset);
	}

	private DWARFAttributeValue injectError(long offset, DWARFAttributeValue attribute,
			DWARFForm form) {
		switch (form) {
			case DW_FORM_addr:
				return new DWARFNumericAttribute(0);

			// Block Form
			case DW_FORM_block4:
			case DW_FORM_block2:
			case DW_FORM_block1:
			case DW_FORM_block:
				return new DWARFBlobAttribute(new byte[] {});

			// Constant Form
			case DW_FORM_data8:
			case DW_FORM_data4:
			case DW_FORM_data2:
			case DW_FORM_data1:
			case DW_FORM_udata:
			case DW_FORM_sdata:
				return new DWARFNumericAttribute(0);

			// Exprloc Form
			case DW_FORM_exprloc:
				return new DWARFBlobAttribute(new byte[] {});

			case DW_FORM_flag_present:
			case DW_FORM_flag:
				return DWARFBooleanAttribute.TRUE;

			// Pointer Types Form (lineptr, loclistptr, macptr, rangelistptr)
			case DW_FORM_sec_offset:
				return new DWARFNumericAttribute(0);

			// Reference Form
			case DW_FORM_ref8:
			case DW_FORM_ref4:
			case DW_FORM_ref2:
			case DW_FORM_ref1:
			case DW_FORM_ref_udata:
			case DW_FORM_ref_addr:
				return new DWARFNumericAttribute(0);

			// String Form
			case DW_FORM_strp:
			case DW_FORM_string:
				return new DWARFStringAttribute("");

			case DW_FORM_indirect:
			case NULL:
			default:
				throw new IllegalArgumentException("Invalid DWARF Form: " + form);
		}
	}
}

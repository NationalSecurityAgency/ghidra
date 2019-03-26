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
package ghidra.app.util.bin.format.dwarf4.encoding;

import java.util.HashMap;
import java.util.Map;

/**
 * DWARF attribute encoding consts from www.dwarfstd.org/doc/DWARF4.pdf
 */
public enum DWARFForm {
	NULL(0x0),
	DW_FORM_addr(0x1),
	DW_FORM_block2(0x3),
	DW_FORM_block4(0x4),
	DW_FORM_data2(0x5),
	DW_FORM_data4(0x6),
	DW_FORM_data8(0x7),
	DW_FORM_string(0x8),
	DW_FORM_block(0x9),
	DW_FORM_block1(0xa),
	DW_FORM_data1(0xb),
	DW_FORM_flag(0xc),
	DW_FORM_sdata(0xd),
	DW_FORM_strp(0xe),
	DW_FORM_udata(0xf),
	DW_FORM_ref_addr(0x10),
	DW_FORM_ref1(0x11),
	DW_FORM_ref2(0x12),
	DW_FORM_ref4(0x13),
	DW_FORM_ref8(0x14),
	DW_FORM_ref_udata(0x15),
	DW_FORM_indirect(0x16),
	DW_FORM_sec_offset(0x17),
	DW_FORM_exprloc(0x18),
	DW_FORM_flag_present(0x19),
	DW_FORM_ref_sig8(0x20);

	private final int value;

	private static final Map<Integer, DWARFForm> valueMap;

	static {
		valueMap = new HashMap<>();
		for (DWARFForm access : DWARFForm.values()) {
			valueMap.put(access.getValue(), access);
		}
	}

	private DWARFForm(int value) {
		this.value = value;
	}

	/**
	 * Get the integer value of this enum.
	 * @return the integer value of the enum
	 */
	public int getValue() {
		return this.value;
	}

	/**
	 * Find the form value given a Number value.
	 * @param key Number value to check
	 * @return DWARFForm enum if it exists
	 * @throws IllegalArgumentException if the key is not found
	 */
	public static DWARFForm find(int key) {
		DWARFForm access = valueMap.get(key);
		if (access != null) {
			return access;
		}
		throw new IllegalArgumentException("Invalid Integer value: " + key);
	}
}

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
 * DWARF identifier case consts from www.dwarfstd.org/doc/DWARF4.pdf
 */
public enum DWARFIdentifierCase
{
	DW_ID_case_sensitive(0x0),
	DW_ID_up_case(0x1),
	DW_ID_down_case(0x2),
	DW_ID_case_insensitive(0x3);
	
	private final int value;
	
	private static final Map<Integer, DWARFIdentifierCase> valueMap;
	
	static {
		valueMap = new HashMap<Integer, DWARFIdentifierCase>();
		for(DWARFIdentifierCase access : DWARFIdentifierCase.values()) {
			valueMap.put(access.getValue(), access);
		}
	}
	
	private DWARFIdentifierCase(int value) {
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
	 * Find the identifier case value given a Number value.
	 * @param key Number value to check
	 * @return DWARFIdentifierCase enum if it exists
	 * @throws IllegalArgumentException if the key is not found 
	 */
	public static DWARFIdentifierCase find(long key) {
		DWARFIdentifierCase access = valueMap.get((int) key);
		if(access != null)
			return access;
		throw new IllegalArgumentException("Invalid Integer value: " + key);
	}
}

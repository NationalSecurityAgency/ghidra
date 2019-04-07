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
 * DWARF accessibility consts from www.dwarfstd.org/doc/DWARF4.pdf
 */
public enum DWARFAccessibility
{
	DW_ACCESS_public(0x1),
	DW_ACCESS_protected(0x2),
	DW_ACCESS_private(0x3);
	
	private final int value;
	
	private static final Map<Integer, DWARFAccessibility> valueMap;
	
	static {
		valueMap = new HashMap<Integer, DWARFAccessibility>();
		for(DWARFAccessibility access : DWARFAccessibility.values()) {
			valueMap.put(access.getValue(), access);
		}
	}
	
	private DWARFAccessibility(int value) {
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
	 * Find the accessibility value given a Number value.
	 * @param key Number value to check
	 * @return DWARFAccessibility enum if it exists
	 * @throws IllegalArgumentException if the key is not found 
	 */
	public static DWARFAccessibility find(Number key) { 
		DWARFAccessibility access = valueMap.get(key.intValue());
		if(access != null)
			return access;
		throw new IllegalArgumentException("Invalid Integer value: " + key.toString());
	}
}

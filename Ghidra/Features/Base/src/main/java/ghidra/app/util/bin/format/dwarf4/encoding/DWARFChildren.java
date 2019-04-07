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
 * DWARF child determination consts from www.dwarfstd.org/doc/DWARF4.pdf.
 * <p>
 * Yes, its a direct equiv to a boolean, but its in the spec.
 */
public enum DWARFChildren
{
	DW_CHILDREN_no(0),
	DW_CHILDREN_yes(1);
	
	private final int value;
	
	private static final Map<Integer, DWARFChildren> valueMap;
	
	static {
		valueMap = new HashMap<Integer, DWARFChildren>();
		for(DWARFChildren access : DWARFChildren.values()) {
			valueMap.put(access.getValue(), access);
		}
	}
	
	private DWARFChildren(int value) {
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
	 * Find the children value given a Number value.
	 * @param key Number value to check
	 * @return DWARFChildren enum if it exists
	 * @throws IllegalArgumentException if the key is not found 
	 */
	public static DWARFChildren find(Number key) { 
		DWARFChildren access = valueMap.get(key.intValue());
		if(access != null)
			return access;
		throw new IllegalArgumentException("Invalid Integer value: " + key.toString());
	}
}

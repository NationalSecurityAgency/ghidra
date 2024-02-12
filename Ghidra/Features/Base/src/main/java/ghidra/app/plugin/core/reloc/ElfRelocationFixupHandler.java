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
package ghidra.app.plugin.core.reloc;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.format.elf.relocation.ElfRelocationType;

public abstract class ElfRelocationFixupHandler extends RelocationFixupHandler {

	private Map<Integer, ElfRelocationType> relocationTypesMap;

	/**
	 * Abstract constructor for an {@link ElfRelocationFixupHandler}.
	 * 
	 * @param relocationEnumClass specifies the {@link ElfRelocationType} enum which defines
	 * all supported relocation types for this relocation handler.
	 */
	protected ElfRelocationFixupHandler(Class<? extends ElfRelocationType> relocationEnumClass) {
		initRelocationTypeMap(relocationEnumClass);
	}

	private void initRelocationTypeMap(Class<? extends ElfRelocationType> relocationEnumClass) {
		if (!relocationEnumClass.isEnum() ||
			!ElfRelocationType.class.isAssignableFrom(relocationEnumClass)) {
			throw new IllegalArgumentException(
				"Invalid class specified - expected enum which implements ElfRelocationType: " +
					relocationEnumClass.getName());
		}
		relocationTypesMap = new HashMap<>();
		for (ElfRelocationType t : relocationEnumClass.getEnumConstants()) {
			relocationTypesMap.put(t.typeId(), t);
		}
	}

	/**
	 * Get the relocation type enum value which corresponds to the specified type value.
	 * 
	 * @param type relocation type value
	 * @return relocation type enum value or null if type not found or this handler was not
	 * constructed with a {@link ElfRelocationType} enum class.  The returned value may be
	 * safely cast to the relocation enum class specified during handler construction.
	 */
	public ElfRelocationType getRelocationType(int type) {
		if (relocationTypesMap == null) {
			return null;
		}
		return relocationTypesMap.get(type);
	}

}

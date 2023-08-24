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
package ghidra.app.util.bin.format.elf.relocation;

import java.util.*;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;

class RISCV_ElfRelocationContext extends ElfRelocationContext {

	protected RISCV_ElfRelocationContext(ElfRelocationHandler handler, ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		super(handler, loadHelper, symbolMap);
	}

	/**
	 * <code>OffsetComparator</code> provides ability to compare a Long ElfSymbol offset value with an
	 * ElfRelocation object's relocation offset.
	 */
	private static class OffsetComparator implements Comparator<Object> {

		public static final OffsetComparator INSTANCE = new OffsetComparator();

		@Override
		public int compare(Object o1, Object o2) {
			if (o1 instanceof Long) {
				return -compare(o2, o1);
			}
			ElfRelocation rel = (ElfRelocation) o1;
			long relOffset = rel.getOffset();
			long offset = (Long) o2;
			if (relOffset == offset) {
				return 0;
			}
			return Long.compareUnsigned(relOffset, offset);
		}

	}

	/**
	 * Find the HI20 relocation whose offset matches the value of of the specified symbol.
	 * @param hi20Symbol ELF symbol which corresponds to HI20 relocation
	 * @return matching relocation or null if not found
	 */
	ElfRelocation getHi20Relocation(ElfSymbol hi20Symbol) {

		Long symValue = hi20Symbol.getValue();

		// Search for first relocation within table whose offset matches the specified hi20Symbol value
		ElfRelocation[] relocations = relocationTable.getRelocations();
		int relIndex = Arrays.binarySearch(relocations, symValue, OffsetComparator.INSTANCE);
		if (relIndex < 0) {
			return null; // relocation not found
		}
		// back-up in the event there is more than one matching relocation offset
		while (relIndex > 0 && relocations[relIndex - 1].getOffset() == symValue) {
			--relIndex;
		}
		// look for hi20 relocation
		while (relIndex < relocations.length && relocations[relIndex].getOffset() == symValue) {
			int type = relocations[relIndex].getType();
			if ((type == RISCV_ElfRelocationConstants.R_RISCV_PCREL_HI20) ||
				(type == RISCV_ElfRelocationConstants.R_RISCV_GOT_HI20)) {
				return relocations[relIndex];
			}
			++relIndex;
		}
		return null;
	}
}

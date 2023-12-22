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
package ghidra.app.plugin.core.codebrowser;

import java.util.Objects;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * A record for information about an {@link AddressRange}, used when creating
 * address range tables
 * 
 * @param min smallest address in range
 * @param max largest address in range
 * @param size number of addresses in range
 * @param isSameByte true precisely when all of the bytes in the range have the same value or 
 * all are undefined
 * @param numRefsTo number of references to this range
 * @param numRefsFrom number of references out of this range
 */
public record AddressRangeInfo(Address min, Address max, long size, boolean isSameByte,
		int numRefsTo, int numRefsFrom) {

	/**
	 * Returns true precisely when all of the addresses between min and max (inclusive)
	 * have the same byte value OR all addresses are without values
	 * 
	 * @param min minimum address
	 * @param max maximum address
	 * @param program program
	 * @return true if all addresses have same value
	 */
	public static boolean isSameByteValue(Address min, Address max, Program program) {
		//throws an IllegalArgumentException if min,max don't defined a proper AddressRange
		AddressSet range = new AddressSet(min, max);
		AddressSetView loadedAndInit = program.getMemory().getLoadedAndInitializedAddressSet();
		if (!range.intersects(loadedAndInit)) {
			return true; //range has no values
		}
		if (!loadedAndInit.contains(range)) {
			return false; //range contains some address with values and some without
			//this might be impossible
		}
		try {
			Byte firstByte = program.getMemory().getByte(min);
			for (Address addr = min.add(1); addr.compareTo(max) <= 0; addr = addr.add(1)) {
				Byte val = program.getMemory().getByte(addr);

				if (!Objects.equals(val, firstByte)) {
					return false;
				}
			}
		}
		catch (MemoryAccessException e) {
			return false; //shouldn't happen
		}
		return true;
	}

}

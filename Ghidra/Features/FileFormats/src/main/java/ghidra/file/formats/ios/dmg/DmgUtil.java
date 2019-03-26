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
package ghidra.file.formats.ios.dmg;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

import java.util.Arrays;

public final class DmgUtil {

	public final static boolean isDMG(Program program) {
		if (program != null) {
			Address address = program.getMinAddress();
			if (address != null) {
				byte [] bytes = new byte[8];
				try {
					program.getMemory().getBytes(address, bytes);
				}
				catch (MemoryAccessException e) {
				}
				return Arrays.equals(bytes, DmgConstants.DMG_MAGIC_BYTES_v1) ||
                       Arrays.equals(bytes, DmgConstants.DMG_MAGIC_BYTES_v2);
			}
		}
		return false;
	}

}

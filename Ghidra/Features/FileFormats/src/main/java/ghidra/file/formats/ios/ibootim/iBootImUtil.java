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
package ghidra.file.formats.ios.ibootim;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

import java.util.Arrays;

public class iBootImUtil {

	public final static boolean isiBootIm(Program program) {
		if (program != null) {
			Address address = program.getMinAddress();
			if (address != null) {
				byte [] bytes = getBytes(program, address);
				if (Arrays.equals(bytes, iBootImConstants.SIGNATURE_BYTES)) {
					return true;
				}
			}
		}
		return false;
	}

	private static byte [] getBytes(Program program, Address address) {
		byte [] bytes = new byte[iBootImConstants.SIGNATURE_LENGTH];
		try {
			program.getMemory().getBytes(address, bytes);
		}
		catch (MemoryAccessException e) {
		}
		return bytes;
	}
}

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
package ghidra.file.formats.lzss;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

import java.util.Arrays;

public class LzssUtil {

	public final static boolean isLZSS(Program program) {
		if (program != null) {
			Address address = program.getMinAddress();
			if (address != null) {
				byte [] compressionBytes = getBytes(program, address);
				if (Arrays.equals(compressionBytes, LzssConstants.SIGNATURE_COMPRESSION_BYTES)) {
					byte [] formatBytes = getBytes(program, address.add(compressionBytes.length));
					if (Arrays.equals(formatBytes, LzssConstants.SIGNATURE_LZSS_BYTES)) {
						return true;
					}
				}
			}
		}
		return false;
	}

	private static byte [] getBytes(Program program, Address address) {
		byte [] bytes = new byte[4];
		try {
			program.getMemory().getBytes(address, bytes);
		}
		catch (MemoryAccessException e) {
		}
		return bytes;
	}

}

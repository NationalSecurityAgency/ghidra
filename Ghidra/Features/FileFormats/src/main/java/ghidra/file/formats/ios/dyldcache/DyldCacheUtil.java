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
package ghidra.file.formats.ios.dyldcache;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotYetImplementedException;

public final class DyldCacheUtil {

	public final static boolean isDyldCache(Program program) {
		if (program == null) {
			return false;
		}
		if (program.getMemory().getSize() < DyldArchitecture.DYLD_V1_SIGNATURE_LEN) {
			return false;
		}
		byte [] bytes = new byte[ DyldArchitecture.DYLD_V1_SIGNATURE_LEN ];
		try {
			Address address = program.getMinAddress();
			program.getMemory().getBytes(address, bytes);
		}
		catch (MemoryAccessException e) {
		}
		return isDyldCache(new String(bytes).trim());
	}

	public final static boolean isDyldCache(ByteProvider provider) {
		throw new NotYetImplementedException();
	}

	public final static boolean isDyldCache(String signature) {
		for (DyldArchitecture architecture : DyldArchitecture.ARCHITECTURES) {
			if (architecture.getSignature().equals(signature)) {
				return true;
			}
		}
		return false;
	}

}

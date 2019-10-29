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
package ghidra.app.util.opinion;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.dyld.DyldArchitecture;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Utilities methods for working with Mach-O DYLD shared cache binaries.
 */
public class DyldCacheUtils {

	/**
	 * Determines if the given {@link Program} is a DYLD cache.
	 * 
	 * @param program The {@link Program}
	 * @return True if the given {@link Program} is a DYLD cache; otherwise, false
	 */
	public final static boolean isDyldCache(Program program) {
		if (program == null) {
			return false;
		}
		if (program.getMemory().getSize() < DyldArchitecture.DYLD_V1_SIGNATURE_LEN) {
			return false;
		}
		byte[] bytes = new byte[DyldArchitecture.DYLD_V1_SIGNATURE_LEN];
		try {
			Address address = program.getMinAddress();
			program.getMemory().getBytes(address, bytes);
		}
		catch (MemoryAccessException e) {
			return false;
		}
		return isDyldCache(new String(bytes).trim());
	}

	/**
	 * Determines if the given {@link ByteProvider} is a DYLD cache.
	 * 
	 * @param provider The {@link ByteProvider}
	 * @return True if the given {@link ByteProvider} is a DYLD cache; otherwise, false
	 */
	public final static boolean isDyldCache(ByteProvider provider) {
		if (provider == null) {
			return false;
		}
		byte[] bytes = new byte[DyldArchitecture.DYLD_V1_SIGNATURE_LEN];
		try {
			bytes = provider.readBytes(0, DyldArchitecture.DYLD_V1_SIGNATURE_LEN);
		}
		catch (IOException e) {
			return false;
		}
		return isDyldCache(new String(bytes).trim());
	}

	/**
	 * Determines if the given signature represents a DYLD cache signature with an architecture we
	 * support.
	 * 
	 * @param signature The DYLD cache signature
	 * @return True if the given signature represents a DYLD cache signature with an architecture we
	 * support; otherwise, false
	 */
	public final static boolean isDyldCache(String signature) {
		for (DyldArchitecture architecture : DyldArchitecture.ARCHITECTURES) {
			if (architecture.getSignature().equals(signature)) {
				return true;
			}
		}
		return false;
	}

}

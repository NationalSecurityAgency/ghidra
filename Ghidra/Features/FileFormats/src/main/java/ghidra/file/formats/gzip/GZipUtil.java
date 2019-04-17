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
package ghidra.file.formats.gzip;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.listing.Program;

import java.util.Arrays;

public class GZipUtil {
	
	public final static boolean isGZip( Program program ) {
		ByteProvider provider = new MemoryByteProvider( program.getMemory(), 
														program.getAddressFactory().getDefaultAddressSpace() );
		return isGZip( provider );
	}

	public final static boolean isGZip( ByteProvider provider ) {
		try {
			byte [] bytes = provider.readBytes( 0, GZipConstants.MAGIC_BYTES.length  );
			return Arrays.equals( bytes, GZipConstants.MAGIC_BYTES );
		}
		catch (Exception e) {
		}
		return false;
	}

	public final static boolean isGZip( byte [ ] bytes ) {
		if ( bytes.length >= GZipConstants.MAGIC_BYTES.length ) {
			return bytes[ 0 ] == GZipConstants.MAGIC_BYTES[ 0 ] && bytes[ 1 ] == GZipConstants.MAGIC_BYTES[ 1 ];
		}
		return false;
	}
}

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
package ghidra.file.formats.bplist;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

import java.io.IOException;

public final class BinaryPropertyListUtil {

	public static boolean isBinaryPropertyList( ByteProvider provider ) throws IOException {
		byte [] bytes = provider.readBytes( 0, BinaryPropertyListConstants.BINARY_PLIST_MAGIC.length( ) );
		String magic = new String( bytes );
		return BinaryPropertyListConstants.BINARY_PLIST_MAGIC.equals( magic );
	}

	public static boolean isBinaryPropertyList( Memory memory, Address address ) {
		byte [] bytes = new byte [ BinaryPropertyListConstants.BINARY_PLIST_MAGIC.length( ) ];
		try {
			memory.getBytes( address, bytes );
		}
		catch ( Exception e ) {
			// ignore
		}
		String magic = new String( bytes );
		return BinaryPropertyListConstants.BINARY_PLIST_MAGIC.equals( magic );
	}

	public static String generateName( int index ) {
		return generateName( index & 0xffffffffL );
	}

	public static String generateName( long index ) {
		return "BPLIST_Index_" + Long.toHexString( index );
	}
}

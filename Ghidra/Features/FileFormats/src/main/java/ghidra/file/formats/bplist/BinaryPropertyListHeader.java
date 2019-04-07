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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class BinaryPropertyListHeader implements StructConverter {

	private String magic;
	private byte majorVersion;
	private byte minorVersion;

	private BinaryPropertyListTrailer trailer;

	public BinaryPropertyListHeader( BinaryReader reader ) throws IOException {

		if ( reader.isLittleEndian( ) ) {
			throw new IOException( "BinaryReader must be BIG endian!" );
		}

		magic = reader.readNextAsciiString( BinaryPropertyListConstants.BINARY_PLIST_MAGIC.length( ) );

		if ( !BinaryPropertyListConstants.BINARY_PLIST_MAGIC.equals( magic ) ) {
			throw new IOException( "Not a valid binary PLIST" );
		}

		majorVersion = reader.readNextByte( );
		minorVersion = reader.readNextByte( );

		if ( majorVersion != BinaryPropertyListConstants.MAJOR_VERSION_0 ) {
			throw new IOException( "Unsupported binary PLIST version: " + majorVersion + "." + minorVersion );
		}

		trailer = new BinaryPropertyListTrailer( reader );
	}

	public BinaryPropertyListTrailer getTrailer() {
		return trailer;
	}


	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "bplist", 0 );
		structure.add( STRING, BinaryPropertyListConstants.BINARY_PLIST_MAGIC.length( ), "magic", null );
		structure.add( BYTE, "majorVersion", null );
		structure.add( BYTE, "minorVersion", null );
		return structure;
	}
}

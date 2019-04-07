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

public class BinaryPropertyListTrailer implements StructConverter {

	private long trailerIndex;

	private int offsetSize;
	private int objectRefSize;
	private int objectCount;
	private int topObject;
	private int offsetTableOffset;
	private int [] offsetTable;

	public BinaryPropertyListTrailer( BinaryReader reader ) throws IOException {
		trailerIndex = reader.length( ) - BinaryPropertyListConstants.TRAILER_SIZE;

		offsetSize = reader.readByte( trailerIndex + 6 ) & 0xff;
		objectRefSize = reader.readByte( trailerIndex + 7 ) & 0xff;
		objectCount = reader.readInt( trailerIndex + 12 ) & 0xffffffff;
		topObject = reader.readInt( trailerIndex + 20 ) & 0xffffffff;
		offsetTableOffset = reader.readInt( trailerIndex + 28 ) & 0xffffffff;

		// if ( offsetSize != 4 ) {
		// throw new IOException( "Unsupported binary PLIST offset size: " +
		// offsetSize );
		// }

		offsetTable = new int [ objectCount ];

		for ( int i = 0 ; i < objectCount ; ++i ) {
			if ( offsetSize == 4 ) {
				offsetTable[ i ] = reader.readInt( offsetTableOffset + i * offsetSize );
			}
			else if ( offsetSize == 2 ) {
				offsetTable[ i ] = reader.readShort( offsetTableOffset + i * offsetSize ) & 0xffff;
			}
			else if ( offsetSize == 1 ) {
				offsetTable[ i ] = reader.readByte( offsetTableOffset + i * offsetSize ) & 0xff;
			}
			else {
				throw new RuntimeException( "Invalid offset size in binary PList" );
			}
		}
	}

	public int getOffsetSize() {
		return offsetSize;
	}

	public int getObjectRefSize() {
		return objectRefSize;
	}

	public int getObjectCount() {
		return objectCount;
	}

	public int getTopObject() {
		return topObject;
	}

	public int getOffsetTableOffset() {
		return offsetTableOffset;
	}

	public int [] getOffsetTable() {
		return offsetTable;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "bplist_trailer", 0 );
		structure.add( BYTE, "unk0", null );
		structure.add( BYTE, "unk1", null );
		structure.add( BYTE, "unk2", null );
		structure.add( BYTE, "unk3", null );
		structure.add( BYTE, "unk4", null );
		structure.add( BYTE, "unk5", null );
		structure.add( BYTE, "offsetSize", null );
		structure.add( BYTE, "objectRefSize", null );
		structure.add( QWORD, "objectCount", null );
		structure.add( QWORD, "topObject", null );
		structure.add( QWORD, "offsetTableOffset", null );
		return structure;
	}

	public long getTrailerIndex() {
		return trailerIndex;
	}

}

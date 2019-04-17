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
package ghidra.file.formats.ios.btree;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Map Record.
 * 
 * @see <a href="https://developer.apple.com/library/archive/technotes/tn/tn1150.html">Map Record</a> 
 */
public class BTreeMapRecord implements StructConverter {

	private byte [] bitmap;

	protected BTreeMapRecord( BinaryReader reader, BTreeHeaderRecord headerRecord ) throws IOException {
		this.bitmap  =  reader.readNextByteArray( headerRecord.getNodeSize() - 256 );
	}

	/**
	 * Returns the map record node allocation bitmap.
	 * @return the map record node allocation bitmap
	 */
	public byte [] getBitmap() {
		return bitmap;
	}

	/**
	 * Returns  true if the specified node index is used.
	 * Returns false if the specified node index is free.
	 * @param nodeIndex the node index
	 * @return true if the specified node index is used, false if free
	 */
	public boolean isNodeUsed( int nodeIndex ) {
		int block = bitmap[ nodeIndex / 8 ] & 0xff;
		return ( block & ( 1 << 7 - ( nodeIndex  % 8 ) ) ) != 0;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType( this );
	}
}

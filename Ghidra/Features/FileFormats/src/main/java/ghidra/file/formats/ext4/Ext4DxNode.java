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
package ghidra.file.formats.ext4;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class Ext4DxNode implements StructConverter {

	private int fake_inode;
	private short fake_rec_len;
	private byte name_len;
	private byte file_type;
	private short limit;
	private short count;
	private int block;
	private Ext4DxEntry[] entries;
	
	public Ext4DxNode(ByteProvider provider) throws IOException {
		this( new BinaryReader( provider, true ) );
	}
	
	public Ext4DxNode(BinaryReader reader) throws IOException {
		fake_inode = reader.readNextInt();
		fake_rec_len = reader.readNextShort();
		name_len = reader.readNextByte();
		file_type = reader.readNextByte();
		limit = reader.readNextShort();
		count = reader.readNextShort();
		block = reader.readNextInt();
		entries = new Ext4DxEntry[count];
		for( int i = 0; i < count; i++ ) {
			entries[i] = new Ext4DxEntry(reader);
		}
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		// TODO Auto-generated method stub
		return null;
	}

}

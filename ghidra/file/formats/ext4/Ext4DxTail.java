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
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class Ext4DxTail implements StructConverter {

	private int dt_reserved;
	private int dt_checksum;
	
	public Ext4DxTail(ByteProvider provider) throws IOException {
		this( new BinaryReader( provider, true ) );
	}
	
	public Ext4DxTail(BinaryReader reader) throws IOException {
		dt_reserved = reader.readNextInt();
		dt_checksum = reader.readNextInt();
	}
	
	public int getDt_resered() {
		return dt_reserved;
	}

	public int getDt_checksum() {
		return dt_checksum;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("dx_tail", 0);
		structure.add(DWORD, "dt_reserved", null);
		structure.add(DWORD, "dt_checksum", null);
		return structure;
	}

}

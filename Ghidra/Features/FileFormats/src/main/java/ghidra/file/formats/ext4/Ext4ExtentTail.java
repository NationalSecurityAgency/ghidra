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

public class Ext4ExtentTail implements StructConverter {

	private int eb_checksum;
	
	public Ext4ExtentTail( ByteProvider provider ) throws IOException {
		this( new BinaryReader( provider, true ) );
	}
	
	public Ext4ExtentTail( BinaryReader reader ) throws IOException {
		eb_checksum = reader.readNextInt();
	}
	
	public int getEb_checksum() {
		return eb_checksum;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("ext4_extent_tail", 0);
		structure.add(DWORD, "eb_checksum", null);
		return structure;
	}

}

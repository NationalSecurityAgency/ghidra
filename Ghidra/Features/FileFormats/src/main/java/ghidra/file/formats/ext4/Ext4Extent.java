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

public class Ext4Extent implements StructConverter {

	private int ee_block;
	private short ee_len;
	private short ee_start_hi;
	private int ee_start_lo;
	
	public Ext4Extent(ByteProvider provider) throws IOException {
		this( new BinaryReader( provider, true ) );
	}
	
	public Ext4Extent( BinaryReader reader ) throws IOException {
		ee_block = reader.readNextInt();
		ee_len = reader.readNextShort();
		ee_start_hi = reader.readNextShort();
		ee_start_lo = reader.readNextInt();
	}
	
	public int getEe_block() {
		return ee_block;
	}

	public short getEe_len() {
		return ee_len;
	}

	public short getEe_start_hi() {
		return ee_start_hi;
	}

	public int getEe_start_lo() {
		return ee_start_lo;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("ext4_extent", 0);
		structure.add(DWORD, "ee_block", null);
		structure.add(WORD, "ee_len", null);
		structure.add(WORD, "ee_start_hi", null);
		structure.add(DWORD, "ee_start_lo", null);
		return structure;
	}

}

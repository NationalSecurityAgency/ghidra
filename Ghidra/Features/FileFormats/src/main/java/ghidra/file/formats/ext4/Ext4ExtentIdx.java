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

public class Ext4ExtentIdx implements StructConverter {

	private int ei_block;
	private int ei_leaf_lo;
	private short ei_leaf_hi;
	private short ei_unused;
	
	public Ext4ExtentIdx(ByteProvider provider) throws IOException {
		this( new BinaryReader( provider, true ) );
	}
	
	public Ext4ExtentIdx(BinaryReader reader) throws IOException {
		ei_block = reader.readNextInt();
		ei_leaf_lo = reader.readNextInt();
		ei_leaf_hi = reader.readNextShort();
		ei_unused = reader.readNextShort();
	}
	
	public int getEi_block() {
		return ei_block;
	}

	public int getEi_leaf_lo() {
		return ei_leaf_lo;
	}

	public short getEi_leaf_hi() {
		return ei_leaf_hi;
	}

	/**
	 * Return the calculated ei_leaf value by combining ei_leaf_lo and ei_leaf_hi
	 * 
	 * @return the calculated ei_leaf value by combining ei_leaf_lo and ei_leaf_hi
	 */
	public long getEi_leaf() {
		return (Short.toUnsignedLong(ei_leaf_hi) << 32) | Integer.toUnsignedLong(ei_leaf_lo);
	}

	public short getEi_unused() {
		return ei_unused;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("ext4_extent_idx", 0);
		structure.add(DWORD, "ei_block", null);
		structure.add(DWORD, "ei_leaf_lo", null);
		structure.add(WORD, "ei_leaf_hi", null);
		structure.add(WORD, "ei_unused", null);
		return structure;
	}

}

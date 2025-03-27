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
package ghidra.app.util.bin.format.omf.omf51;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.omf.OmfString;
import ghidra.app.util.bin.format.omf.OmfUtils;

public class Omf51ExternalDef {

	// ID Block Types
	public static final int ID_BLOCK_SEGMENT = 0;
	public static final int ID_BLOCK_RELOCATABLE = 1;
	public static final int ID_BLOCK_EXTERNAL = 2;

	private byte blockType;
	private int extId;
	private byte info;
	private OmfString name;

	/**
	 * Creates a new {@link Omf51ExternalDef}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the external definition
	 * @param largeSegmentId True if the external ID is 2 bytes; false if 1 byte
	 * @throws IOException if an IO-related error occurred
	 */
	public Omf51ExternalDef(BinaryReader reader, boolean largeSegmentId) throws IOException {
		blockType = reader.readNextByte();
		extId = largeSegmentId ? reader.readNextUnsignedShort() : reader.readNextUnsignedByte();
		info = reader.readNextByte();
		reader.readNextByte(); // unused
		name = OmfUtils.readString(reader);
	}

	/**
	 * {@return the block type (should always be 2 - ID_BLOCK_EXTERNAL}
	 */
	public byte getBlockType() {
		return blockType;
	}
	
	/**
	 * {@return the external reference id}
	 */
	public int getExtId() {
		return extId;
	}

	/**
	 * {@return the symbol info}
	 */
	public byte getInfo() {
		return info;
	}

	/**
	 * {@return the symbol name}
	 */
	public OmfString getName() {
		return name;
	}

	/**
	 * {@return the usage type (CODE, XDATA, etc)}
	 */
	public int getUsageType() {
		return info & 0x07;
	}

	/**
	 * {@return whether or not this symbol is a variable or not}
	 */
	public boolean isVariable() {
		return (info & 0x40) != 0;
	}
	
	/**
	 * {@return whether or not this procedure is fixed to a register bank}
	 */
	public boolean isFixedReg() {
		return (info & 0x20) != 0;
	}
	
	/**
	 * {@return the register bank this procedure is fixed to}
	 */
	public int getRegBank() {
		return (info & 0x18) >> 7;
	}
}

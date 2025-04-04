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

public class Omf51Fixup {

	// Reference Types
	public static final int REF_TYPE_LOW = 0;
	public static final int REF_TYPE_BYTE = 1;
	public static final int REF_TYPE_RELATIVE = 2;
	public static final int REF_TYPE_HIGH = 3;
	public static final int REF_TYPE_WORD = 4;
	public static final int REF_TYPE_INBLOCK = 5;
	public static final int REF_TYPE_BIT = 6;
	public static final int REF_TYPE_CONV = 7;

	// ID Block Types
	public static final int ID_BLOCK_SEGMENT = 0;
	public static final int ID_BLOCK_RELOCATABLE = 1;
	public static final int ID_BLOCK_EXTERNAL = 2;

	private int refLoc;
	private byte refType;
	private byte blockType;
	private int blockId;
	private int offset;

	/**
	 * Creates a new {@link Omf51Fixup}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the fixup
	 * @param largeBlockId True if the block ID is 2 bytes; false if 1 byte
	 * @throws IOException if an IO-related error occurred
	 */
	public Omf51Fixup(BinaryReader reader, boolean largeBlockId) throws IOException {
		refLoc = reader.readNextUnsignedShort();
		refType = reader.readNextByte();
		blockType = reader.readNextByte();
		blockId = largeBlockId ? reader.readNextUnsignedShort() : reader.readNextUnsignedByte();
		offset = reader.readNextUnsignedShort();
	}

	/**
	 * {@return the reference location (REFLOC)}
	 */
	public int getRefLoc() {
		return refLoc;
	}
	
	/**
	 * {@return the reference type (REF TYP)}
	 */
	public int getRefType() {
		return refType;
	}
	
	/**
	 * {@return the operand block type (ID BLK)}
	 */
	public int getBlockType() {
		return blockType;
	}
	
	/**
	 * {@return the operand id (segment ID or EXT ID)}
	 */
	public int getBlockId() {
		return blockId;
	}

	/**
	 * {@return the operand offset}
	 */
	public int getOffset() {
		return offset;
	}
}

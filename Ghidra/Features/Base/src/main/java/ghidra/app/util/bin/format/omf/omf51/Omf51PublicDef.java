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

public class Omf51PublicDef {

	// Usage Types
	public static final int CODE = 0;
	public static final int XDATA = 1;
	public static final int DATA = 2;
	public static final int IDATA = 3;
	public static final int BIT = 4;
	public static final int NUMBER = 5;

	// Register Banks
	public static final int REG_BANK_0 = 0;
	public static final int REG_BANK_1 = 1;
	public static final int REG_BANK_2 = 2;
	public static final int REG_BANK_3 = 3;

	private int segId;
	private byte info;
	private int offset;
	private OmfString name;

	/**
	 * Creates a new {@link Omf51PublicDef}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the public definition
	 * @param largeSegmentId True if the segment ID is 2 bytes; false if 1 byte
	 * @throws IOException if an IO-related error occurred
	 */
	public Omf51PublicDef(BinaryReader reader, boolean largeSegmentId) throws IOException {
		segId = largeSegmentId ? reader.readNextUnsignedShort() : reader.readNextUnsignedByte();
		info = reader.readNextByte();
		offset = reader.readNextUnsignedShort();
		reader.readNextByte(); // unused
		name = OmfUtils.readString(reader);
	}

	/**
	 * {@return the segment id}
	 */
	public int getSegId() {
		return segId;
	}

	/**
	 * {@return the segment info}
	 */
	public byte getInfo() {
		return info;
	}

	/**
	 * {@return the offset into the segment}
	 */
	public int getOffset() {
		return offset;
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
	 * {@return whether or not this procedure is indirectly callable}
	 */
	public boolean isIndirectlyCallable() {
		return (info & 0x80) != 0;
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

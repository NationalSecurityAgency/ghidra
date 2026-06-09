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

public class Omf51Segment {

	// Segment Types
	public static final int CODE = 0;
	public static final int XDATA = 1;
	public static final int DATA = 2;
	public static final int IDATA = 3;
	public static final int BIT = 4;

	// Relocation Types
	public static final int ABS = 0;
	public static final int UNIT = 1;
	public static final int BITADDRESSABLE = 2;
	public static final int INPAGE = 3;
	public static final int INBLOCK = 4;
	public static final int PAGE = 5;

	private int id;
	private byte info;
	private byte relType;
	private int base;
	private int size;
	private OmfString name;

	/**
	 * Creates a new {@link Omf51Segment}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the segment definition
	 * @param largeSegmentId True if the segment ID is 2 bytes; false if 1 byte
	 * @throws IOException if an IO-related error occurred
	 */
	public Omf51Segment(BinaryReader reader, boolean largeSegmentId) throws IOException {
		id = largeSegmentId ? reader.readNextUnsignedShort() : reader.readNextUnsignedByte();
		info = reader.readNextByte();
		relType = reader.readNextByte();
		reader.readNextByte(); // unused
		base = reader.readNextUnsignedShort();
		size = reader.readNextUnsignedShort();
		name = OmfUtils.readString(reader);

		// Size of 0 is used to represent 0x10000
		if (size == 0) {
			size = 0x10000;
		}

		// Size is ignored if empty bit is set, but force it to be 0 for consistency
		if ((info & 0x8) != 0) {
			size = 0;
		}
	}

	/**
	 * {@return the segment id}
	 */
	public int id() {
		return id;
	}

	/**
	 * {@return the segment info}
	 */
	public byte info() {
		return info;
	}

	/**
	 * {@return the segment relocation type}
	 */
	public byte relType() {
		return relType;
	}

	/**
	 * {@return the segment base address}
	 */
	public int base() {
		return base;
	}

	/**
	 * {@return the segment size}
	 */
	public int size() {
		return size;
	}

	/**
	 * {@return the segment name}
	 */
	public OmfString name() {
		return name;
	}

	/**
	 * {@return the segment type (CODE, XDATA, etc)}
	 */
	public int getType() {
		return info & 7;
	}

	/**
	 * {@return whether or not this segment is code}
	 */
	public boolean isCode() {
		return getType() == CODE;
	}

	/**
	 * {@return whether or not this segment is absolute}
	 */
	public boolean isAbsolute() {
		return id == 0;
	}
}

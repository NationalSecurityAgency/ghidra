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
package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a SOM {@code aux_id} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomAuxId implements StructConverter {

	/** The size in bytes of a {@link SomAuxId} */
	public static final int SIZE = 0x8;

	private boolean mandatory;
	private boolean copy;
	private boolean append;
	private boolean ignore;
	private int reserved;
	private int type;
	private long length;

	/**
	 * Creates a new {@link SomAuxId}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the auxiliary ID
	 * @throws IOException if there was an IO-related error
	 */
	public SomAuxId(BinaryReader reader) throws IOException {
		int bitfield = reader.readNextInt();
		type = bitfield & 0xffff;
		reserved = (bitfield >> 16) & 0xfff;
		ignore = ((bitfield >> 28) & 0x1) != 0;
		append = ((bitfield >> 29) & 0x1) != 0;
		copy = ((bitfield >> 30) & 0x1) != 0;
		mandatory = ((bitfield >> 31) & 0x1) != 0;
		length = reader.readNextUnsignedInt();
	}

	/**
	 * {@return whether or not this auxiliary header contains information that the linker must 
	 * understand}
	 */
	public boolean getMandatory() {
		return mandatory;
	}

	/**
	 * {@return whether or not this auxiliary header is to be copied without modification to any new
	 * SOM created from this SOM}
	 */
	public boolean getCopy() {
		return copy;
	}

	/**
	 * {@return whether or not this auxiliary header is to be copied without modification to any new
	 * SOM created from this SOM, except that multiple entries with the same type and append set of
	 * “action flags” (i.e., mandatory, copy, append, ignore) should be merged (concatenation of the
	 * data portion)}
	 */
	public boolean getAppend() {
		return append;
	}

	/**
	 * {@return whether or not this auxiliary header should be ignored if its type field is unknown
	 * (i.e., do not copy, do not merge)}
	 */
	public boolean getIgnore() {
		return ignore;
	}

	/**
	 * {@return the reserved value}
	 */
	public int getReserved() {
		return reserved;
	}

	/**
	 * {@return the type of auxiliary header}
	 * 
	 * @see SomConstants
	 */
	public int getType() {
		return type;
	}

	/**
	 * {@return the length of the auxiliary header in bytes (this value does NOT include the two
	 * word identifiers at the front of the header)}
	 */
	public long getLength() {
		return length;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("aux_id", SIZE);
		struct.setPackingEnabled(true);
		try {
			struct.addBitField(DWORD, 1, "mandatory", null);
			struct.addBitField(DWORD, 1, "copy", null);
			struct.addBitField(DWORD, 1, "append", null);
			struct.addBitField(DWORD, 1, "ignore", null);
			struct.addBitField(DWORD, 12, "reserved", null);
			struct.addBitField(DWORD, 16, "type", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.add(DWORD, "length", null);
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}

}

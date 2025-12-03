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
 * Represents a SOM {@code shlib_list_entry} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomShlibListEntry implements StructConverter {

	/** The size in bytes of a {@link SomShlibListEntry} */
	public static final int SIZE = 0x8;
	
	private String shlibName;
	private int reserved1;
	private boolean internalName;
	private boolean dashLReference;
	private int bind;
	private short highwaterMark;

	/**
	 * Creates a new {@link SomShlibListEntry}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the header
	 * @param stringTableLoc The location of the string table
	 * @throws IOException if there was an IO-related error
	 */
	public SomShlibListEntry(BinaryReader reader, long stringTableLoc) throws IOException {
		shlibName = reader.readAsciiString(stringTableLoc + reader.readNextInt());
		int bitfield = reader.readNextUnsignedByte();
		dashLReference = (bitfield & 0x1) != 0;
		internalName = ((bitfield >> 1) & 0x1) != 0;
		reserved1 = (bitfield >> 2) & 0x3f;
		bind = reader.readNextUnsignedByte();
		highwaterMark = reader.readNextShort();
	}

	/**
	 * {@return the name of the shared library}
	 */
	public String getShlibName() {
		return shlibName;
	}

	/**
	 * {@return the reserved value}
	 */
	public int getReserved1() {
		return reserved1;
	}

	/**
	 * {@return whether or not the shared library entry is an internal name}
	 */
	public boolean isInternalName() {
		return internalName;
	}

	/**
	 * {@return whether or not the shared library was specified on the link line with
	 * the {@code -l} option or not}
	 */
	public boolean getDashLReference() {
		return dashLReference;
	}

	/**
	 * {@return the binding-time preference}
	 */
	public int getBind() {
		return bind;
	}

	/**
	 * {@return the {@code highwater_mark} value}
	 */
	public short getHighwaterMark() {
		return highwaterMark;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("shlib_list_entry", SIZE);
		struct.setPackingEnabled(true);
		struct.add(DWORD, "shlib_name", "offset withing string table");
		try {
			struct.addBitField(BYTE, 6, "reserved1", "");
			struct.addBitField(BYTE, 1, "internal_name", "shlib entry is an internal name");
			struct.addBitField(BYTE, 1, "dash_l_reference", "referenced with -lc or absolute path");
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.add(BYTE, "bind", "BIND_IMMEDIATE, BIND_DEFERRED or BIND_REFERENCE");
		struct.add(WORD, "highwater_mark", "highwater mark of the library");
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}

}

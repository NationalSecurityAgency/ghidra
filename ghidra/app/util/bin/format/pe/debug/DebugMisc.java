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
package ghidra.app.util.bin.format.pe.debug;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.OffsetValidator;
import ghidra.program.model.data.*;
import ghidra.util.Conv;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the <code>IMAGE_DEBUG_MISC</code> struct
 * as defined in <b><code>winnt.h</code></b>.
 * <br>
 * 
 * <pre>
 * typedef struct _IMAGE_DEBUG_MISC {
 *     DWORD       DataType;               // type of misc data, see defines
 *     DWORD       Length;                 // total length of record, rounded to four
 *                                         // byte multiple.
 *     BOOLEAN     Unicode;                // TRUE if data is unicode string
 *     BYTE        Reserved[ 3 ];
 *     BYTE        Data[ 1 ];              // Actual data
 * }
 * </pre>
 */
public class DebugMisc implements StructConverter {
	/**
	 * The name to use when converting into a structure data type.
	 */
	public final static String NAME = "IMAGE_DEBUG_MISC";

	private final static byte IMAGE_DEBUG_MISC_EXENAME = 1;

	private DebugDirectory debugDir;
	private int dataType;
	private int length;
	private boolean unicode;
	private byte[] reserved;
	private String actualData;

	/**
	 * Constructor
	 * @param reader the binary reader
	 * @param debugDir the debug directory associated to this MISC debug
	 * @param ntHeader 
	 */
	static DebugMisc createDebugMisc(FactoryBundledWithBinaryReader reader,
			DebugDirectory debugDir, OffsetValidator validator) throws IOException {
		DebugMisc debugMisc = (DebugMisc) reader.getFactory().create(DebugMisc.class);
		debugMisc.initDebugMisc(reader, debugDir, validator);
		return debugMisc;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public DebugMisc() {
	}

	private void initDebugMisc(FactoryBundledWithBinaryReader reader, DebugDirectory debugDir,
			OffsetValidator validator) throws IOException {
		this.debugDir = debugDir;

		long oldIndex = reader.getPointerIndex();

		long index = debugDir.getPointerToRawData() & Conv.INT_MASK;
		if (!validator.checkPointer(index)) {
			Msg.error(this, "Invalid file index " + Long.toHexString(index));
			return;
		}
		reader.setPointerIndex(index);

		dataType = reader.readNextInt();
		length = reader.readNextInt();
		unicode = reader.readNextByte() == 1;
		reserved = reader.readNextByteArray(3);
		if (length > 0) {
			actualData =
				(unicode ? reader.readNextUnicodeString(length) : reader.readNextAsciiString());
		}
		else {
			Msg.error(this, "Bad string length " + Integer.toHexString(length));
		}

		reader.setPointerIndex(oldIndex);
	}

	/**
	 * Returns the data type of this misc debug.
	 * @return the data type of this misc debug
	 */
	public int getDataType() {
		return dataType;
	}

	/**
	 * Returns the length of this misc debug.
	 * @return the length of this misc debug
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Returns true if this misc debug is unicode.
	 * @return true if this misc debug is unicode
	 */
	public boolean isUnicode() {
		return unicode;
	}

	/**
	 * Returns the array of reserved bytes.
	 * @return the array of reserved bytes
	 */
	public byte[] getReserved() {
		return reserved;
	}

	/**
	 * Returns a string equivalent of the actual misc debug data.
	 * @return a string equivalent of the actual misc debug data
	 */
	public String getActualData() {
		return actualData;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		if (getDataType() == DebugMisc.IMAGE_DEBUG_MISC_EXENAME) {
			return "Misc Debug Information: " + getActualData();
		}
		return "Unknown Misc Debug Information Type: " + getDataType();
	}

	/**
	 * Returns the debug directory associated with this misc debug.
	 * @return the debug directory associated with this misc debug
	 */
	public DebugDirectory getDebugDirectory() {
		return debugDir;
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {

		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, "DataType", "type of misc data, see defines");
		struct.add(DWORD, "Length", "total length of record, rounded to four byte multiple");
		struct.add(BYTE, "Unicode", "TRUE if data is unicode string");
		struct.add(new ArrayDataType(BYTE, 3, 1), "Reserved[3]", null);
		if (isUnicode()) {
			struct.add(new UnicodeDataType(), length - 12, "Data[]", "Actual data");
		}
		else {
			struct.add(new StringDataType(), length - 12, "Data[]", "Actual data");
		}

		return struct;
	}
}

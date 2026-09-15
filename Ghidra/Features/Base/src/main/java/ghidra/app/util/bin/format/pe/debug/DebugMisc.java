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
import java.util.Objects;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.pe.OffsetValidator;
import ghidra.program.model.data.*;
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
	 * Creates a new {@link DebugMisc}
	 * 
	 * @param reader the binary reader
	 * @param debugDir the debug directory associated to this MISC debug
	 * @param validator the {@link OffsetValidator}
	 * @throws IOException if an IO-related exception occurred
	 */
	DebugMisc(BinaryReader reader, DebugDirectory debugDir, OffsetValidator validator)
			throws IOException {
		this.debugDir = debugDir;

		long oldIndex = reader.getPointerIndex();

		long index = Integer.toUnsignedLong(debugDir.getPointerToRawData());
		if (!validator.checkPointer(index)) {
			Msg.error(this, "Invalid file index 0x%x".formatted(index));
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
		else if (length == 0 && !unicode) {
			actualData = reader.readNextAsciiString();
			// NB: should be a multiple of 4 per winnt.h 
			// 13 = len(start of struct) + null
			length = (int) Math.ceil((actualData.length() + 13) / 4.0) * 4;
			if (length > DebugDirectory.IMAGE_SIZEOF_DEBUG_DIRECTORY) {
				length = DebugDirectory.IMAGE_SIZEOF_DEBUG_DIRECTORY;
			}
			Msg.warn(this, "Zero length structure - defaulting to " + Integer.toHexString(length));
		}
		else {
			Msg.error(this, "Bad structure length: 0x%x".formatted(length));
		}

		reader.setPointerIndex(oldIndex);
	}

	/**
	 *{@return the data type of this misc debug}
	 */
	public int getDataType() {
		return dataType;
	}

	/**
	 * {@return the length of this misc debug}
	 */
	public int getLength() {
		return length;
	}

	/**
	 * {@return true if this misc debug is unicode}
	 */
	public boolean isUnicode() {
		return unicode;
	}

	/**
	 * {@return the array of reserved bytes}
	 */
	public byte[] getReserved() {
		return reserved;
	}

	/**
	 * {@return a string equivalent of the actual misc debug data, or {@code null} if this structure
	 * is invalid}
	 */
	public String getActualData() {
		return actualData;
	}

	@Override
	public String toString() {
		if (getDataType() == DebugMisc.IMAGE_DEBUG_MISC_EXENAME) {
			return "Misc Debug Information: " + Objects.toString(actualData, "<null>");
		}
		return "Unknown Misc Debug Information Type: " + getDataType();
	}

	/**
	 * {@return the debug directory associated with this misc debug}
	 */
	public DebugDirectory getDebugDirectory() {
		return debugDir;
	}

	@Override
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

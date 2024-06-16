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
package ghidra.file.formats.dtb;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.NumericUtilities;
import ghidra.util.StringUtilities;
import ghidra.util.exception.DuplicateNameException;

/**
 * Class to represent a Flattened Device Tree (FDT) Property. 
 *
 * @see <a href="https://android.googlesource.com/platform/external/dtc/+/refs/heads/master/libfdt/fdt.h#41">include/fdt.h</a>
 */
public class FdtProperty implements StructConverter {

	private int tag;
	private int length;
	private int nameOffset;
	private byte[] data;

	public FdtProperty(BinaryReader reader) throws IOException {
		tag = reader.readNextInt();
		length = reader.readNextInt();
		nameOffset = reader.readNextInt();

		length = (int) NumericUtilities.getUnsignedAlignedValue(length, 4);

		data = (length == 0) ? new byte[0] : reader.readNextByteArray(length);
	}

	/**
	 * Returns the FDT Property Tag.
	 * @see FdtConstants
	 * @return the FDT Property Tag
	 */
	public int getTag() {
		return tag;
	}

	/**
	 * Returns the FDT Property length.
	 * @return the FDT Property length
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Returns the offset to the FDT Property name.
	 * @return the offset to the FDT Property name
	 */
	public int getNameOffset() {
		return nameOffset;
	}

	/**
	 * Returns the FDT Property data bytes.
	 * @return the FDT Property data bytes
	 */
	public byte[] getData() {
		return data;
	}

	/**
	 * Returns the FDT Property data bytes as a readable string.
	 * @return the FDT Property data bytes as a readable string
	 */
	public String getDataAsString() {
		if (length > 0) {
			if (StringUtilities.isAsciiChar(data[0])) {
				return new String(data).trim();
			}
			else {
				return NumericUtilities.convertBytesToString(data);
			}
		}
		return "<empty>";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure =
			new StructureDataType(getDataTypeName(), 0);
		structure.add(DWORD, "tag", null);
		structure.add(DWORD, "len", null);
		structure.add(DWORD, "nameoff", null);
		if (length > 0) {
			if (StringUtilities.isAsciiChar(data[0])) {
				structure.add(STRING, length, "data", null);
			}
			else {
				DataType array = new ArrayDataType(BYTE, length, BYTE.getLength());
				structure.add(array, length, "data", null);
			}
		}
		return structure;
	}

	/**
	 * Generates the name for this FDT property.
	 * @return the name for this FDT property
	 */
	private String getDataTypeName() {
		String name = "fdt_property_" + length;
		if (length > 0 && StringUtilities.isAsciiChar(data[0])) {
			return name + "_s";
		}
		return name;
	}

}

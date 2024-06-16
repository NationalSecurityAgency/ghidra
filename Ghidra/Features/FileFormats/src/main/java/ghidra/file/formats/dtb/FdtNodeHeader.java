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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.DuplicateNameException;

/**
 * Class to represent a Flattened Device Tree (FDT) Node. 
 *
 * @see <a href="https://android.googlesource.com/platform/external/dtc/+/refs/heads/master/libfdt/fdt.h#36">include/fdt.h</a>
 */
public class FdtNodeHeader implements StructConverter {

	private int tag;
	private String name;

	private int nameLength = 0;

	public FdtNodeHeader(BinaryReader reader) throws IOException {
		tag = reader.readNextInt();
		name = reader.readAsciiString(reader.getPointerIndex());//peek it

		nameLength = (int) NumericUtilities.getUnsignedAlignedValue(name.length() + 1, 4);

		name = reader.readNextAsciiString(nameLength);
	}

	/**
	 * Returns the FDT Node Tag.
	 * @see FdtConstants
	 * @return the FDT Node Tag
	 */
	public int getTag() {
		return tag;
	}

	/**
	 * Returns the FDT Node Name.
	 * @return the FDT Node name
	 */
	public String getName() {
		return name;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String structureName = "fdt_node_header_" + name.length();
		StructureDataType structure = new StructureDataType(structureName, 0);
		structure.add(DWORD, "tag", null);
		structure.add(STRING, nameLength, "name", null);
		return structure;
	}

}

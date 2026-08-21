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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents an unknown SOM auxiliary header 
 */
public class SomUnknownAuxHeader extends SomAuxHeader {

	private byte[] bytes;

	/**
	 * Creates a new {@link SomUnknownAuxHeader}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the auxiliary header
	 * @throws IOException if there was an IO-related error
	 */
	public SomUnknownAuxHeader(BinaryReader reader) throws IOException {
		super(reader);
		bytes = reader.readNextByteArray((int) auxId.getLength());
	}

	/**
	 * {@return the unknown bytes of this auxiliary header}
	 */
	public byte[] getBytes() {
		return bytes;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("som_unknown_auxhdr", 0);
		struct.setPackingEnabled(true);
		struct.add(auxId.toDataType(), "som_auxhdr", null);
		struct.add(new ArrayDataType(BYTE, (int) auxId.getLength(), 1), "bytes", null);
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}

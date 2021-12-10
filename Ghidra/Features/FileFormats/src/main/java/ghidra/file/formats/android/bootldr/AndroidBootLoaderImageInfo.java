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
package ghidra.file.formats.android.bootldr;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class AndroidBootLoaderImageInfo implements StructConverter {

	private String name;
	private int size;

	public AndroidBootLoaderImageInfo(BinaryReader reader) throws IOException {
		name = reader.readNextAsciiString(AndroidBootLoaderConstants.IMG_INFO_NAME_LENGTH).trim();
		size = reader.readNextInt();
	}

	public String getName() {
		return name;
	}

	public int getSize() {
		return size;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(AndroidBootLoaderConstants.IMG_INFO_NAME, 0);
		struct.add(STRING, AndroidBootLoaderConstants.IMG_INFO_NAME_LENGTH, "magic", null);
		struct.add(DWORD, "size", null);
		return struct;
	}

}

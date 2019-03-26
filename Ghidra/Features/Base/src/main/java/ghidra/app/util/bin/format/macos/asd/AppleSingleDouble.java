/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.macos.asd;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macos.MacException;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class AppleSingleDouble implements StructConverter {

	public final static int SINGLE_MAGIC_NUMBER = 0x00051600;
	public final static int DOUBLE_MAGIC_NUMBER = 0x00051607;

	private final static int FILLER_LEN = 16;

	private int     magicNumber;
	private int     versionNumber;
	private byte [] filler;
	private short   numberOfEntries;

	private List<EntryDescriptor> entryList = new ArrayList<EntryDescriptor>();

	public AppleSingleDouble(ByteProvider provider) throws IOException, MacException {
		BinaryReader reader = new BinaryReader(provider, false);

		magicNumber     = reader.readNextInt();

		if (magicNumber != SINGLE_MAGIC_NUMBER && magicNumber != DOUBLE_MAGIC_NUMBER) {
			throw new MacException("Invalid Apple Single/Double file");
		}

		versionNumber   = reader.readNextInt();
		filler          = reader.readNextByteArray(FILLER_LEN);
		numberOfEntries = reader.readNextShort();

		for (int i = 0 ; i < numberOfEntries ; ++i) {
			entryList.add(new EntryDescriptor(reader));
		}
	}

	public int getMagicNumber() {
		return magicNumber;
	}
	public int getVersionNumber() {
		return versionNumber;
	}
	public byte [] getFiller() {
		return filler;
	}
	public short getNumberOfEntries() {
		return numberOfEntries;
	}

	public List<EntryDescriptor> getEntryList() {
		return entryList;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = StructConverterUtil.parseName(AppleSingleDouble.class);
		Structure struct = new StructureDataType(name, 0);
		struct.add(DWORD, "magicNumber", null);
		struct.add(DWORD, "versionNumber", null);
		struct.add(new ArrayDataType(BYTE, FILLER_LEN, BYTE.getLength()), "filler", null);
		struct.add(WORD, "numberOfEntries", null);
		return struct;
	}

}

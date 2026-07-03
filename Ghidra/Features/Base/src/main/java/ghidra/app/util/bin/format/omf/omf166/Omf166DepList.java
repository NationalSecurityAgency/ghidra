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
package ghidra.app.util.bin.format.omf.omf166;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.omf.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Omf166DepList extends OmfRecord {

	public record InfoEntry(byte type, Byte mark, Integer time, OmfString name) {}

	private List<InfoEntry> info = new ArrayList<>();

	public Omf166DepList(BinaryReader reader) throws IOException {
		super(reader);
	}

	/**
	 * {@return the {@link Omf166DepList} "info"}
	 */
	public List<InfoEntry> getInfo() {
		return info;
	}

	@Override
	public void parseData() throws IOException, OmfException {
		while (dataReader.getPointerIndex() < dataEnd) {
			byte iTyp = dataReader.readNextByte();
			switch (iTyp) {
				case 0x00:
				case 0x01:
				case 0x02:
				case 0x03:
				case 0x04:
					byte mark = dataReader.readNextByte();
					int time = dataReader.readNextInt();
					OmfString name = OmfUtils.readString(dataReader);
					info.add(new InfoEntry(iTyp, mark, time, name));
					break;
				case (byte) 0xff:
					OmfString invocation = OmfUtils.readString(dataReader);
					if (invocation.length() == 0) {
						// We assume that a "big string" follows
						invocation = OmfUtils.readBigString(dataReader);
					}
					info.add(new InfoEntry(iTyp, null, null, invocation));
					break;
				default:
					throw new OmfException("Unexpected DEPLST iTyp: 0x%x".formatted(iTyp));
			}
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(Omf166RecordTypes.getName(recordType), 0);
		struct.add(BYTE, "type", null);
		struct.add(WORD, "length", null);
		for (InfoEntry entry : info) {
			struct.add(BYTE, "iTyp", null);
			if (entry.mark != null) {
				struct.add(BYTE, "mark8", null);
			}
			if (entry.time != null) {
				struct.add(DWORD, "time32", null);
			}
			if (entry.name().isBig()) {
				OmfString empty = new OmfString(0, "", false);
				struct.add(empty.toDataType(), empty.getDataTypeSize(), "empty", null);
			}
			struct.add(entry.name.toDataType(), entry.name.getDataTypeSize(), "name", null);
		}
		struct.add(BYTE, "checksum", null);
		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}
}

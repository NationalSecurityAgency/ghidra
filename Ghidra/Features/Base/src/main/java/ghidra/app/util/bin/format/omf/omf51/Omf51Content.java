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
package ghidra.app.util.bin.format.omf.omf51;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.omf.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Omf51Content extends OmfRecord {

	private byte segId;
	private int offset;
	private byte[] dataBytes;

	/**
	 * Creates a new {@link Omf51Content} record
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @throws IOException if an IO-related error occurred
	 */
	public Omf51Content(BinaryReader reader) throws IOException {
		super(reader);
	}

	@Override
	public void parseData() throws IOException, OmfException {
		segId = dataReader.readNextByte();
		offset = dataReader.readNextUnsignedShort();
		dataBytes = dataReader.readNextByteArray((int) (dataEnd - dataReader.getPointerIndex()));
	}

	/**
	 * {@return the segment ID}
	 */
	public byte getSegId() {
		return segId;
	}

	/**
	 * {@return the offset}
	 */
	public int getOffset() {
		return offset;
	}

	/**
	 * {@return the data}
	 */
	public byte[] getDataBytes() {
		return dataBytes;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(Omf51RecordTypes.getName(recordType), 0);
		struct.add(BYTE, "type", null);
		struct.add(WORD, "length", null);
		struct.add(BYTE, "SEG ID", null);
		struct.add(WORD, "offset", null);
		if (dataBytes.length > 0) {
			struct.add(new ArrayDataType(BYTE, dataBytes.length, 1), "data", null);
		}
		struct.add(BYTE, "checksum", null);

		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}
}

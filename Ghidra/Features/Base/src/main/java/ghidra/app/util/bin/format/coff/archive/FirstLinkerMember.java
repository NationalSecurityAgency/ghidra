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
package ghidra.app.util.bin.format.coff.archive;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.DataConverter;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class FirstLinkerMember implements StructConverter {

	private int numberOfSymbols;
	private int [] offsets;
	private List<String> stringTable = new ArrayList<String>();

	private long _fileOffset;
	private List<Integer> stringLengths = new ArrayList<Integer>();

	public FirstLinkerMember(BinaryReader reader, CoffArchiveMemberHeader header, boolean skip)
			throws IOException {
		_fileOffset = reader.getPointerIndex();

		boolean isLittleEndian = reader.isLittleEndian();
		reader.setLittleEndian(false);//this entire structure is stored as big-endian..

		numberOfSymbols = readNumberOfSymbols(reader);

		if (skip) {
			reader.setPointerIndex(reader.getPointerIndex() + (numberOfSymbols * BinaryReader.SIZEOF_INT));
		}
		else {
			offsets = reader.readNextIntArray( numberOfSymbols );
		}

		if (skip) {
			for (int i = 0 ; i < numberOfSymbols ; ++i) {
				String string = reader.readNextAsciiString();
				stringLengths.add( string.length() + 1 );
			}
		}
		else {
			stringTable = new ArrayList<String>(numberOfSymbols);
			for (int i = 0 ; i < numberOfSymbols ; ++i) {
				String string = reader.readNextAsciiString();
				stringTable.add( string );
				stringLengths.add( string.length() + 1 );
			}
		}

		reader.setLittleEndian(isLittleEndian);
		reader.setPointerIndex(_fileOffset + header.getSize());
	}

	/**
	 * The number of symbols field is stored in big-endian format.
	 */
	private int readNumberOfSymbols(BinaryReader reader) throws IOException {
		if (reader.isLittleEndian()) {
			DataConverter dc = BigEndianDataConverter.INSTANCE;
			byte [] bytes = reader.readNextByteArray(4);
			return dc.getInt(bytes);
		}
		return reader.readNextInt();
	}

	public long getFileOffset() {
		return _fileOffset;
	}

	public int getNumberOfSymbols() {
		return numberOfSymbols;
	}

	public int [] getOffsets() {
		if (offsets == null) {
			throw new RuntimeException("FirstLinkerMember::getOffsets() has been skipped.");
		}
		return offsets;
	}

	public List<String> getStringTable() {
		if (stringTable.isEmpty()) {
			throw new RuntimeException("FirstLinkerMember::getStringTable() has been skipped.");
		}
		return new ArrayList<String>(stringTable);
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = StructConverterUtil.parseName(FirstLinkerMember.class);
		Structure struct = new StructureDataType(name + "_" + numberOfSymbols, 0);
		struct.add(DWORD, "numberOfSymbols", null);
		struct.add(new ArrayDataType(DWORD, numberOfSymbols, DWORD.getLength()), "offsets", null);
		for (int i = 0 ; i < stringLengths.size() ; ++i) {
			Integer length = stringLengths.get(i);
			struct.add(STRING, length, "string["+i+"]", null);
		}
		return struct;
	}

}

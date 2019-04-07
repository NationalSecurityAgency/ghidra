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
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class SecondLinkerMember implements StructConverter {

	private int numberOfMembers;
	private int [] offsets;
	private int numberOfSymbols;
	private short [] indices;
	private List<String> stringTable = new ArrayList<String>();

	private long _fileOffset;
	private List<Integer> _stringLengths = new ArrayList<Integer>();

	public SecondLinkerMember(BinaryReader reader, CoffArchiveMemberHeader header, boolean skip)
			throws IOException {
		_fileOffset = reader.getPointerIndex();

		numberOfMembers = reader.peekNextInt();

		boolean isLittleEndian = reader.isLittleEndian();

		if ((numberOfMembers & 0xff000000) != 0 && (numberOfMembers & 0x000000ff) != 0) {
			throw new IOException("Invalid COFF: unable to determine big-endian or little-endian; too many members detected.");
		}
		if ((numberOfMembers & 0xff000000) != 0) {//invert the endian
			reader.setLittleEndian( !reader.isLittleEndian() );
		}

		numberOfMembers = reader.readNextInt();

		if (skip) {
			reader.setPointerIndex(reader.getPointerIndex() + (numberOfMembers * BinaryReader.SIZEOF_INT));
		}
		else {
			offsets = reader.readNextIntArray( numberOfMembers );
		}

		numberOfSymbols = reader.readNextInt();

		if (skip) {
			reader.setPointerIndex(reader.getPointerIndex() + (numberOfSymbols * BinaryReader.SIZEOF_SHORT));
		}
		else {
			indices = reader.readNextShortArray( numberOfSymbols );
		}

		for (int i = 0 ; i < numberOfSymbols ; ++i) {
			String string = reader.readNextAsciiString();
			if (!skip) {
				stringTable.add( string );
			}
			_stringLengths.add( string.length() + 1 );
		}

		reader.setPointerIndex(_fileOffset + header.getSize());
		reader.setLittleEndian(isLittleEndian);
	}

	public long getFileOffset() {
		return _fileOffset;
	}

	public int getNumberOfMembers() {
		return numberOfMembers;
	}

	public int [] getOffsets() {
		if (offsets == null) {
			throw new RuntimeException("SecondLinkerMember::getOffsets() has been skipped.");
		}
		return offsets;
	}

	public int getNumberOfSymbols() {
		return numberOfSymbols;
	}

	public short [] getIndices() {
		if (indices == null) {
			throw new RuntimeException("SecondLinkerMember::getIndices() has been skipped.");
		}
		return indices;
	}

	public List<String> getStringTable() {
		if (stringTable.isEmpty()) {
			throw new RuntimeException("SecondLinkerMember::getStringTable() has been skipped.");
		}
		return new ArrayList<String>(stringTable);
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = StructConverterUtil.parseName(SecondLinkerMember.class);
		String uniqueName = name + "_" + numberOfMembers + "_" + numberOfSymbols;
		Structure struct = new StructureDataType(uniqueName, 0);

		struct.add(DWORD, "numberOfMembers", null);
		struct.add(new ArrayDataType(DWORD, numberOfMembers, DWORD.getLength()), "offsets", null);
		struct.add(DWORD, "numberOfSymbols", null);
		struct.add(new ArrayDataType(WORD, numberOfSymbols, WORD.getLength()), "indices", null);

		for (int i = 0 ; i < _stringLengths.size() ; ++i) {
			Integer length = _stringLengths.get(i);
			struct.add(STRING, length, "string["+i+"]", null);
		}
		return struct;
	}
}

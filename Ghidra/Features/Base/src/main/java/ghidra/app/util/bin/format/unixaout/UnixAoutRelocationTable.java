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
package ghidra.app.util.bin.format.unixaout;

import java.io.IOException;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;

public class UnixAoutRelocationTable implements Iterable<UnixAoutRelocation>, StructConverter {
	private static final int ENTRY_SIZE = 8;

	private final long fileSize;
	private final List<UnixAoutRelocation> relocations;
	private final UnixAoutSymbolTable symtab;

	public UnixAoutRelocationTable(BinaryReader reader, long fileOffset, long fileSize,
			UnixAoutSymbolTable symtab) throws IOException {
		this.fileSize = fileSize;
		this.relocations = new ArrayList<>();
		this.symtab = symtab;

		reader.setPointerIndex(fileOffset);

		// read each relocation table entry
		while (reader.getPointerIndex() < (fileOffset + fileSize)) {
			long address = reader.readNextUnsignedInt();
			long flags = reader.readNextUnsignedInt();

			UnixAoutRelocation relocation =
				new UnixAoutRelocation(address, flags, reader.isBigEndian());
			relocations.add(relocation);
		}
	}

	@Override
	public Iterator<UnixAoutRelocation> iterator() {
		return relocations.iterator();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String dtName = "relocation_info";
		Structure struct = new StructureDataType(new CategoryPath("/AOUT"), dtName, 0);
		struct.setPackingEnabled(true);
		try {
			struct.add(DWORD, "r_address", null);
			struct.addBitField(DWORD, 24, "r_symbolnum", null);
			struct.addBitField(BYTE, 1, "r_pcrel", null);
			struct.addBitField(BYTE, 2, "r_length", null);
			struct.addBitField(BYTE, 1, "r_extern", null);
			struct.addBitField(BYTE, 1, "r_baserel", null);
			struct.addBitField(BYTE, 1, "r_jmptable", null);
			struct.addBitField(BYTE, 1, "r_relative", null);
			struct.addBitField(BYTE, 1, "r_copy", null);
		}
		catch (InvalidDataTypeException e) {
			throw new RuntimeException(e);
		}

		return new ArrayDataType(struct, (int) (fileSize / ENTRY_SIZE), ENTRY_SIZE);
	}

	public void markup(Program program, MemoryBlock block)
			throws CodeUnitInsertionException, DuplicateNameException, IOException {
		Listing listing = program.getListing();
		Data array = listing.createData(block.getStart(), toDataType());

		int idx = 0;
		for (UnixAoutRelocation relocation : this) {
			String name = relocation.getSymbolName(symtab);

			if (!StringUtils.isBlank(name)) {
				Data structData = array.getComponent(idx);
				structData.setComment(CommentType.EOL, name);
			}

			idx++;
		}
	}
}

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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;

public class UnixAoutStringTable {
	private final BinaryReader reader;
	private final long fileOffset;

	public UnixAoutStringTable(BinaryReader reader, long fileOffset, long fileSize) {
		this.reader = reader;
		this.fileOffset = fileOffset;
	}

	public String readString(long stringOffset) {
		if (fileOffset < 0) {
			return null;
		}
		try {
			return reader.readUtf8String(fileOffset + stringOffset).trim();
		}
		catch (IOException e) {
			// FIXME
		}
		return null;
	}

	public void markup(Program program, MemoryBlock block) throws CodeUnitInsertionException {
		Listing listing = program.getListing();
		Address address = block.getStart();
		listing.createData(address, StructConverter.DWORD);

		int strlen = 4;
		while ((address.getOffset() + strlen) < block.getEnd().getOffset()) {
			address = address.add(strlen);
			Data str = listing.createData(address, TerminatedStringDataType.dataType, -1);
			strlen = str.getLength();
		}
	}
}

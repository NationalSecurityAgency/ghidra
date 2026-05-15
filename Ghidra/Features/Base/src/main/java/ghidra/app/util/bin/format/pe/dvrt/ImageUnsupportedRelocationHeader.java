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
package ghidra.app.util.bin.format.pe.dvrt;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PeUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents an unsupported dynamic value relocation header
 */
public class ImageUnsupportedRelocationHeader extends AbstractImageDynamicRelocationHeader {

	private byte[] data;

	/**
	 * Creates a new {@link ImageUnsupportedRelocationHeader}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 * @param size The size in bytes of this header's data
	 * @throws IOException if there was an IO-related error
	 */
	public ImageUnsupportedRelocationHeader(BinaryReader reader, long rva, int size)
			throws IOException {
		super(rva);
		data = reader.readNextByteArray(size);
	}

	/**
	 * {@return the data associated with the unknown header}
	 */
	public byte[] getData() {
		return data;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {
		Address imageBase = program.getImageBase();
		PeUtils.createData(program, imageBase.add(rva), toDataType(), log);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return new ArrayDataType(BYTE, data.length, 1);
	}
}

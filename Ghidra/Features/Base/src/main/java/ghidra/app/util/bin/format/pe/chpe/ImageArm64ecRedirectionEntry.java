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
package ghidra.app.util.bin.format.pe.chpe;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a {@code IMAGE_ARM64EC_REDIRECTION_ENTRY} structure
 */
public class ImageArm64ecRedirectionEntry implements StructConverter, PeMarkupable {

	private int source;
	private int destination;

	private long rva;

	/**
	 * Creates a new {@link ImageArm64ecRedirectionEntry}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 * @throws IOException if there was an IO-related error
	 */
	public ImageArm64ecRedirectionEntry(BinaryReader reader, long rva) throws IOException {
		this.rva = rva;

		source = reader.readNextInt();
		destination = reader.readNextInt();
	}

	/**
	 * {@return the source RVA}
	 */
	public int getSource() {
		return source;
	}

	/**
	 * {@return the destination RVA}
	 */
	public int getDesintation() {
		return destination;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {
		Address imageBase = program.getImageBase();
		DataType dt = toDataType();
		PeUtils.createData(program, imageBase.add(rva), dt, log);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("IMAGE_ARM64EC_REDIRECTION_ENTRY", 0);
		struct.add(IBO32, "Source", null);
		struct.add(IBO32, "Destination", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}

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
package ghidra.app.util.bin.format.pe.cli;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
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
 * The Metadata directory pointed found in {@link ImageCor20Header}.
 */
public class CliMetadataDirectory extends DataDirectory {

	private final static String NAME = "CLI_METADATA_DIRECTORY";

	private CliMetadataRoot metadataRoot;

	public static CliMetadataDirectory createCliMetadataDirectory(NTHeader ntHeader,
			FactoryBundledWithBinaryReader reader) throws IOException {
		CliMetadataDirectory cliMetadataDirectory =
			(CliMetadataDirectory) reader.getFactory().create(CliMetadataDirectory.class);
		cliMetadataDirectory.initCliMetadataDirectory(ntHeader, reader);
		return cliMetadataDirectory;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public CliMetadataDirectory() {
	}

	private void initCliMetadataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
			throws IOException {
		this.ntHeader = ntHeader;
		this.reader = reader;

		this.virtualAddress = reader.readNextInt();
		this.size = reader.readNextInt();
	}

	/**
	 * Gets the Metadata root.
	 * 
	 * @return header The Metadata root.
	 */
	public CliMetadataRoot getMetadataRoot() {
		return metadataRoot;
	}

	@Override
	public String getDirectoryName() {
		return NAME;
	}

	@Override
	public boolean parse() throws IOException {
		int ptr = getPointer();
		if (ptr < 0 || this.size == 0) {
			return false;
		}

		long origIndex = reader.getPointerIndex();
		reader.setPointerIndex(ptr);
		metadataRoot = new CliMetadataRoot(reader, virtualAddress);
		hasParsed = metadataRoot.parse();
		reader.setPointerIndex(origIndex);
		return hasParsed;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {

		if (metadataRoot == null) {
			return;
		}

		monitor.setMessage("[" + program.getName() + "]: CLI metadata...");

		// Get our program address
		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}

		// Create bookmark
		createDirectoryBookmark(program, addr);

		// Create data type
		DataType dt = metadataRoot.toDataType();
		dt.setCategoryPath(new CategoryPath("/PE/CLI"));
		PeUtils.createData(program, addr, dt, log);

		// Markup metadata header
		metadataRoot.markup(program, isBinary, monitor, log, ntHeader);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType ddstruct = new StructureDataType(NAME, 0);
		ddstruct.add(DWordDataType.dataType, "VirtualAddress", null);
		ddstruct.add(DWordDataType.dataType, "Size", null);
		ddstruct.setCategoryPath(new CategoryPath("/PE/CLI"));
		return ddstruct;
	}
}

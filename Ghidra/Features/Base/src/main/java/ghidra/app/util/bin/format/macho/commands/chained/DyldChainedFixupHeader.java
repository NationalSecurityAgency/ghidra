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
package ghidra.app.util.bin.format.macho.commands.chained;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a dyld_chained_fixups_header structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h">mach-o/fixup-chains.h</a> 
 */
public class DyldChainedFixupHeader implements StructConverter {

	private long fixupsVersion;
	private long startsOffset;
	private long importsOffset;
	private long symbolsOffset;
	private long importsCount;
	private int importsFormat;
	private int symbolsFormat;

	private DyldChainedStartsInImage chainedStartsInImage;
	private DyldChainedImports chainedImports;

	/**
	 * Creates a new {@link DyldChainedFixupHeader}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public DyldChainedFixupHeader(BinaryReader reader) throws IOException {
		long ptrIndex = reader.getPointerIndex();

		fixupsVersion = reader.readNextUnsignedInt();
		startsOffset = reader.readNextUnsignedInt();
		importsOffset = reader.readNextUnsignedInt();
		symbolsOffset = reader.readNextUnsignedInt();
		importsCount = reader.readNextUnsignedInt();
		importsFormat = reader.readNextInt();
		symbolsFormat = reader.readNextInt();

		reader.setPointerIndex(ptrIndex + startsOffset);
		chainedStartsInImage = new DyldChainedStartsInImage(reader);

		reader.setPointerIndex(ptrIndex + importsOffset);
		chainedImports = new DyldChainedImports(reader, this);

		reader.setPointerIndex(ptrIndex + symbolsOffset);
		chainedImports.initSymbols(reader, this);
	}

	/**
	 * Marks up this data structure with data structures and comments
	 * 
	 * @param program The {@link Program} to mark up
	 * @param address The {@link Address} of this data structure
	 * @param header The Mach-O header
	 * @param monitor A cancellable task monitor
	 * @param log The log
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void markup(Program program, Address address, MachHeader header, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		try {
			if (startsOffset != 0) {
				Address startsAddr = address.add(startsOffset);
				DataUtilities.createData(program, startsAddr, chainedStartsInImage.toDataType(), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				chainedStartsInImage.markup(program, startsAddr, header, monitor, log);
			}
			if (importsOffset != 0 && symbolsOffset != 0) {
				ReferenceManager referenceManager = program.getReferenceManager();
				Address importsAddr = address.add(importsOffset);
				Address symbolsAddr = address.add(symbolsOffset);
				DyldChainedImport[] chainedImportArray = chainedImports.getChainedImports();
				for (int i = 0; i < importsCount; i++) {
					DyldChainedImport chainedImport = chainedImportArray[i];
					DataType dt = chainedImport.toDataType();
					Data d = DataUtilities.createData(program, importsAddr.add(i * dt.getLength()),
						dt, -1, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
					Address strAddr = symbolsAddr.add(chainedImport.getNameOffset());
					DataUtilities.createData(program,
						symbolsAddr.add(chainedImport.getNameOffset()), STRING, -1,
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
					referenceManager.addMemoryReference(d.getMinAddress(), strAddr, RefType.DATA,
						SourceType.IMPORTED, 0);
				}
			}
		}
		catch (Exception e) {
			log.appendMsg(DyldChainedFixupHeader.class.getSimpleName(),
				"Failed to markup dyld_chained_fixups_header");
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_chained_fixups_header", 0);
		struct.add(DWORD, "fixups_version", "0");
		struct.add(DWORD, "starts_offset", "offset of dyld_chained_starts_in_image in chain_data");
		struct.add(DWORD, "imports_offset", "offset of imports table in chain_data");
		struct.add(DWORD, "symbols_offset", "offset of symbol strings in chain_data");
		struct.add(DWORD, "imports_count", "number of imported symbol names");
		struct.add(DWORD, "imports_format", "DYLD_CHAINED_IMPORT*");
		struct.add(DWORD, "symbols_format", "0 => uncompressed, 1 => zlib compressed");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	public long getFixupsVersion() {
		return fixupsVersion;
	}

	public long getStartsOffset() {
		return startsOffset;
	}

	public long getImportsOffset() {
		return importsOffset;
	}

	public long getSymbolsOffset() {
		return symbolsOffset;
	}

	public long getImportsCount() {
		return importsCount;
	}

	public int getImportsFormat() {
		return importsFormat;
	}

	public int getSymbolsFormat() {
		return symbolsFormat;
	}

	public boolean isCompress() {
		return symbolsFormat != 0;
	}

	public DyldChainedStartsInImage getChainedStartsInImage() {
		return chainedStartsInImage;
	}

	public DyldChainedImports getChainedImports() {
		return chainedImports;
	}
}

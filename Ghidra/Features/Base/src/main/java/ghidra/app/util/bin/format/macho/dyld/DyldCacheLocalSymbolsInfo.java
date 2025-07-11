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
package ghidra.app.util.bin.format.macho.dyld;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.CpuTypes;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.bin.format.macho.commands.NList;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a dyld_cache_local_symbols_info structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h">dyld_cache_format.h</a> 
 */
@SuppressWarnings("unused")
public class DyldCacheLocalSymbolsInfo implements StructConverter {

	private int nlistOffset;
	private int nlistCount;
	private int stringsOffset;
	private int stringsSize;
	private int entriesOffset;
	private int entriesCount;

	private BinaryReader reader;
	private long startIndex;

	private List<NList> nlistList;
	private List<DyldCacheLocalSymbolsEntry> localSymbolsEntryList;
	private boolean is32bit;
	private boolean use64bitOffsets;

	/**
	 * Create a new {@link DyldCacheLocalSymbolsInfo}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD local symbols info
	 * @param architecture The {@link DyldArchitecture}
	 * @param use64bitOffsets True if the DYLD local symbol entries use 64-bit dylib offsets; false
	 *   if they use 32-bit 
	 * @throws IOException if there was an IO-related problem creating the DYLD local symbols info
	 */
	public DyldCacheLocalSymbolsInfo(BinaryReader reader, DyldArchitecture architecture,
			boolean use64bitOffsets) throws IOException {
		this.reader = reader;
		this.startIndex = reader.getPointerIndex();

		nlistOffset = reader.readNextInt();
		nlistCount = reader.readNextInt();
		stringsOffset = reader.readNextInt();
		stringsSize = reader.readNextInt();
		entriesOffset = reader.readNextInt();
		entriesCount = reader.readNextInt();

		nlistList = new ArrayList<>(nlistCount);
		localSymbolsEntryList = new ArrayList<>(entriesCount);

		is32bit = !(architecture.getCpuType() == CpuTypes.CPU_TYPE_ARM_64 ||
			architecture.getCpuType() == CpuTypes.CPU_TYPE_X86_64);

		this.use64bitOffsets = use64bitOffsets;
	}

	/**
	 * Parses the structures referenced by this {@link DyldCacheLocalSymbolsInfo}.
	 * 
	 * @param log The log
	 * @param monitor A cancellable task monitor
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void parse(MessageLog log, TaskMonitor monitor) throws CancelledException {
		parseNList(log, monitor);
		parseLocalSymbols(log, monitor);
	}

	/**
	 * Marks up this {@link DyldCacheLocalSymbolsInfo} with data structures and comments.
	 * 
	 * @param program The {@link Program} to mark up
	 * @param localSymbolsInfoAddr The {@link Address} of the {@link DyldCacheLocalSymbolsInfo}
	 * @param monitor A cancellable task monitor
	 * @param log The log
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void markup(Program program, Address localSymbolsInfoAddr, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		markupLocalSymbols(program, localSymbolsInfoAddr, monitor, log);
		markupNList(program, localSymbolsInfoAddr, monitor, log);
	}

	/**
	 * Gets the {@link List} of {@link DyldCacheLocalSymbolsEntry}s.
	 * 
	 * @return The {@link List} of {@link DyldCacheLocalSymbolsEntry}
	 */
	public List<DyldCacheLocalSymbolsEntry> getLocalSymbolsEntries() {
		return localSymbolsEntryList;
	}

	/**
	 * Gets the {@link List} of {@link NList}.
	 * 
	 * @return The {@link List} of {@link NList}
	 */
	public List<NList> getNList() {
		return nlistList;
	}

	/**
	 * Gets the {@link List} of {@link NList} for the given dylib offset.
	 * 
	 * @param dylibOffset The offset of dylib in the DYLD Cache
	 * @return The {@link List} of {@link NList} for the given dylib offset
	 */
	public List<NList> getNList(long dylibOffset) {
		for (DyldCacheLocalSymbolsEntry entry : localSymbolsEntryList) {
			int index = entry.getNListStartIndex();
			int count = entry.getNListCount();
			if (dylibOffset == entry.getDylibOffset()) {
				return nlistList.subList(index, index + count);
			}
		}
		return List.of();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_local_symbols_info", 0);
		struct.add(DWORD, "nlistOffset", "offset into this chunk of nlist entries");
		struct.add(DWORD, "nlistCount", "count of nlist entries");
		struct.add(DWORD, "stringsOffset", "offset into this chunk of string pool");
		struct.add(DWORD, "stringsSize", "byte count of string pool");
		struct.add(DWORD, "entriesOffset",
			"offset into this chunk of array of dyld_cache_local_symbols_entry ");
		struct.add(DWORD, "entriesCount",
			"number of elements in dyld_cache_local_symbols_entry array");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	private void parseNList(MessageLog log, TaskMonitor monitor) throws CancelledException {
		BinaryReader nListReader =
			new BinaryReader(reader.getByteProvider(), reader.isLittleEndian());
		monitor.setMessage("Parsing DYLD local symbol nlists...");
		monitor.initialize(nlistCount * 2);
		nListReader.setPointerIndex(startIndex + nlistOffset);
		try {

			for (int i = 0; i < nlistCount; ++i) {
				nlistList.add(new NList(nListReader, is32bit));
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
			// sort the entries by the index in the string table, so don't jump around reading
			List<NList> sortedList = nlistList.stream()
					.sorted((o1, o2) -> Integer.compare(o1.getStringTableIndex(),
						o2.getStringTableIndex()))
					.collect(Collectors.toList());

			// initialize the NList strings from string table
			long stringTableOffset = startIndex + stringsOffset;
			for (NList nList : sortedList) {
				monitor.checkCancelled();
				monitor.incrementProgress(1);
				nList.initString(nListReader, stringTableOffset);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(), "Failed to parse nlist.");
		}
	}

	private void parseLocalSymbols(MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Parsing DYLD local symbol entries...");
		monitor.initialize(entriesCount);
		reader.setPointerIndex(startIndex + entriesOffset);
		try {
			for (int i = 0; i < entriesCount; ++i) {
				localSymbolsEntryList.add(new DyldCacheLocalSymbolsEntry(reader, use64bitOffsets));
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(),
				"Failed to parse dyld_cache_local_symbols_entry.");
		}
	}

	private void markupNList(Program program, Address localSymbolsInfoAddr, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD local symbol nlists...");
		monitor.initialize(nlistCount);
		try {
			Address addr = localSymbolsInfoAddr.add(nlistOffset);
			for (NList nlist : nlistList) {
				Data d = program.getListing().createData(addr, nlist.toDataType());
				addr = addr.add(d.getLength());
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(), "Failed to markup nlist.");
		}
	}

	private void markupLocalSymbols(Program program, Address localSymbolsInfoAddr,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD local symbol entries...");
		monitor.initialize(entriesCount);
		try {
			Address addr = localSymbolsInfoAddr.add(entriesOffset);
			for (DyldCacheLocalSymbolsEntry localSymbolsEntry : localSymbolsEntryList) {
				Data d = program.getListing().createData(addr, localSymbolsEntry.toDataType());
				addr = addr.add(d.getLength());
				monitor.checkCancelled();
				monitor.incrementProgress(1);
			}
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(),
				"Failed to markup dyld_cache_local_symbols_entry.");
		}
	}
}

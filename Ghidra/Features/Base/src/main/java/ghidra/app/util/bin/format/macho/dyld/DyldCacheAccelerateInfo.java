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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a dyld_cache_accelerate_info structure.
 * 
 * @see <a href="https://opensource.apple.com/source/dyld/dyld-625.13/launch-cache/dyld_cache_format.h.auto.html">launch-cache/dyld_cache_format.h</a> 
 */
@SuppressWarnings("unused")
public class DyldCacheAccelerateInfo implements StructConverter {

	private int version;
	private int imageExtrasCount;
	private int imagesExtrasOffset;
	private int bottomUpListOffset;
	private int dylibTrieOffset;
	private int dylibTrieSize;
	private int initializersOffset;
	private int initializersCount;
	private int dofSectionsOffset;
	private int dofSectionsCount;
	private int reExportListOffset;
	private int reExportCount;
	private int depListOffset;
	private int depListCount;
	private int rangeTableOffset;
	private int rangeTableCount;
	private long dyldSectionAddr;

	private BinaryReader reader;
	private List<DyldCacheImageInfoExtra> imageInfoExtraList;
	private List<DyldCacheAcceleratorInitializer> acceleratorInitializerList;
	private List<DyldCacheAcceleratorDof> acceleratorDofList;
	private List<DyldCacheRangeEntry> rangeEntryList;

	/**
	 * Create a new {@link DyldCacheAccelerateInfo}.
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of a DYLD accelerate info
	 * @throws IOException if there was an IO-related problem creating the DYLD accelerate info
	 */
	public DyldCacheAccelerateInfo(BinaryReader reader) throws IOException {
		this.reader = reader;

		version = reader.readNextInt();
		imageExtrasCount = reader.readNextInt();
		imagesExtrasOffset = reader.readNextInt();
		bottomUpListOffset = reader.readNextInt();
		dylibTrieOffset = reader.readNextInt();
		dylibTrieSize = reader.readNextInt();
		initializersOffset = reader.readNextInt();
		initializersCount = reader.readNextInt();
		dofSectionsOffset = reader.readNextInt();
		dofSectionsCount = reader.readNextInt();
		reExportListOffset = reader.readNextInt();
		reExportCount = reader.readNextInt();
		depListOffset = reader.readNextInt();
		depListCount = reader.readNextInt();
		rangeTableOffset = reader.readNextInt();
		rangeTableCount = reader.readNextInt();
		dyldSectionAddr = reader.readNextLong();

		imageInfoExtraList = new ArrayList<>(imageExtrasCount);
		acceleratorInitializerList = new ArrayList<>(initializersCount);
		acceleratorDofList = new ArrayList<>(dofSectionsCount);
		rangeEntryList = new ArrayList<>(rangeTableCount);
	}

	/**
	 * Parses the structures referenced by this {@link DyldCacheAccelerateInfo}.
	 * 
	 * @param program The {@link Program} to parse.
	 * @param accelerateInfoAddr The {@link Address} of the {@link DyldCacheAccelerateInfo}
	 * @param log The log
	 * @param monitor A cancellable task monitor
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void parse(Program program, Address accelerateInfoAddr, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		parseImageInfoExtra(program, accelerateInfoAddr, log, monitor);
		parseAcceleratorInitializer(program, accelerateInfoAddr, log, monitor);
		parseAcceleratorDof(program, accelerateInfoAddr, log, monitor);
		parseRangeEntry(program, accelerateInfoAddr, log, monitor);
	}

	/**
	 * Marks up this {@link DyldCacheAccelerateInfo} with data structures and comments.
	 * 
	 * @param program The {@link Program} to mark up
	 * @param accelerateInfoAddr The {@link Address} of the {@link DyldCacheAccelerateInfo}
	 * @param monitor A cancellable task monitor
	 * @param log The log
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void markup(Program program, Address accelerateInfoAddr, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		markupImageInfoExtra(program, accelerateInfoAddr, monitor, log);
		markupAcceleratorInitializer(program, accelerateInfoAddr, monitor, log);
		markupAcceleratorDof(program, accelerateInfoAddr, monitor, log);
		markupReExportList(program, accelerateInfoAddr, monitor, log);
		markupDependencies(program, accelerateInfoAddr, monitor, log);
		markupRangeEntry(program, accelerateInfoAddr, monitor, log);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_cache_accelerate_info", 0);
		struct.add(DWORD, "version", "currently 1");
		struct.add(DWORD, "imageExtrasCount", "does not include aliases");
		struct.add(DWORD, "imagesExtrasOffset",
			"offset into this chunk of first dyld_cache_image_info_extra");
		struct.add(DWORD, "bottomUpListOffset",
			"offset into this chunk to start of 16-bit array of sorted image indexes");
		struct.add(DWORD, "dylibTrieOffset",
			"offset into this chunk to start of trie containing all dylib paths");
		struct.add(DWORD, "dylibTrieSize", "size of trie containing all dylib paths");
		struct.add(DWORD, "initializersOffset",
			"offset into this chunk to start of initializers list");
		struct.add(DWORD, "initializersCount", "size of initializers list");
		struct.add(DWORD, "dofSectionsOffset",
			"offset into this chunk to start of DOF (DTrace object format) sections list");
		struct.add(DWORD, "dofSectionsCount", "size of DOF (DTrace object format sections list)");
		struct.add(DWORD, "reExportListOffset",
			"offset into this chunk to start of 16-bit array of re-exports");
		struct.add(DWORD, "reExportCount", "size of re-exports");
		struct.add(DWORD, "depListOffset",
			"offset into this chunk to start of 16-bit array of dependencies (0x8000 bit set if upward)");
		struct.add(DWORD, "depListCount", "size of dependencies");
		struct.add(DWORD, "rangeTableOffset", "offset into this chunk to start of ss");
		struct.add(DWORD, "rangeTableCount", "size of dependencies");
		struct.add(QWORD, "dyldSectionAddr", "address of libdyld's __dyld section in unslid cache");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	private void parseImageInfoExtra(Program program, Address accelerateInfoAddr, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Parsing DYLD image image info extras...");
		monitor.initialize(imageExtrasCount);
		reader.setPointerIndex(imagesExtrasOffset);
		try {
			for (int i = 0; i < imageExtrasCount; ++i) {
				imageInfoExtraList.add(new DyldCacheImageInfoExtra(reader));
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(),
				"Failed to parse dyld_cache_image_info_extra.");
		}
	}

	private void parseAcceleratorInitializer(Program program, Address accelerateInfoAddr,
			MessageLog log, TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Parsing DYLD accelerator initializers...");
		monitor.initialize(initializersCount);
		reader.setPointerIndex(initializersOffset);
		try {
			for (int i = 0; i < initializersCount; ++i) {
				acceleratorInitializerList.add(new DyldCacheAcceleratorInitializer(reader));
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(),
				"Failed to parse dyld_cache_accelerator_initializer.");
		}
	}

	private void parseAcceleratorDof(Program program, Address accelerateInfoAddr, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Parsing DYLD DOF sections...");
		monitor.initialize(dofSectionsCount);
		reader.setPointerIndex(dofSectionsOffset);
		try {
			for (int i = 0; i < dofSectionsCount; ++i) {
				acceleratorDofList.add(new DyldCacheAcceleratorDof(reader));
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(),
				"Failed to parse dyld_cache_accelerator_dof.");
		}
	}

	private void parseRangeEntry(Program program, Address accelerateInfoAddr, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Parsing DYLD range entries...");
		monitor.initialize(rangeTableCount);
		reader.setPointerIndex(rangeTableOffset);
		try {
			for (int i = 0; i < rangeTableCount; ++i) {
				rangeEntryList.add(new DyldCacheRangeEntry(reader));
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
		}
		catch (IOException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(),
				"Failed to parse dyld_cache_range_entry.");
		}
	}

	private void markupImageInfoExtra(Program program, Address accelerateInfoAddr,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD image info extras...");
		monitor.initialize(imageInfoExtraList.size());
		try {
			Address addr = accelerateInfoAddr.add(imagesExtrasOffset);
			for (DyldCacheImageInfoExtra imageInfoExtra : imageInfoExtraList) {
				Data d = DataUtilities.createData(program, addr, imageInfoExtra.toDataType(), -1,
					false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				addr = addr.add(d.getLength());
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(),
				"Failed to markup dyld_cache_image_info_extra.");
		}
	}

	private void markupAcceleratorInitializer(Program program, Address accelerateInfoAddr,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD accelerator initializers...");
		monitor.initialize(acceleratorInitializerList.size());
		try {
			Address addr = accelerateInfoAddr.add(initializersOffset);
			for (DyldCacheAcceleratorInitializer initializer : acceleratorInitializerList) {
				Data d = DataUtilities.createData(program, addr, initializer.toDataType(), -1,
					false, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				Address funcAddr = program.getImageBase().add(initializer.getFunctionsOffset());
				try {
					program.getFunctionManager().createFunction(null, funcAddr,
						new AddressSet(funcAddr), SourceType.ANALYSIS);
				}
				catch (OverlappingFunctionException | InvalidInputException e) {
					// Function already created...skip
				}
				addr = addr.add(d.getLength());
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(),
				"Failed to markup dyld_cache_accelerator_initializer.");
		}
	}

	private void markupAcceleratorDof(Program program, Address accelerateInfoAddr,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD DOF sections...");
		monitor.initialize(acceleratorDofList.size());
		try {
			Address addr = accelerateInfoAddr.add(dofSectionsOffset);
			for (DyldCacheAcceleratorDof dof : acceleratorDofList) {
				Data d = DataUtilities.createData(program, addr, dof.toDataType(), -1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				addr = addr.add(d.getLength());
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(),
				"Failed to markup dyld_cache_accelerator_dof.");
		}
	}

	private void markupReExportList(Program program, Address accelerateInfoAddr,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD re-exports...");
		monitor.initialize(1);
		try {
			Address addr = accelerateInfoAddr.add(reExportListOffset);
			DataType dt = new ArrayDataType(WORD, reExportCount, WORD.getLength());
			DataUtilities.createData(program, addr, dt, -1, false,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			program.getListing().setComment(addr, CodeUnit.EOL_COMMENT, "re-exports");
			monitor.incrementProgress(1);
		}
		catch (CodeUnitInsertionException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(),
				"Failed to markup reExportList.");
		}
	}

	private void markupDependencies(Program program, Address accelerateInfoAddr,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD dependencies...");
		monitor.initialize(1);
		try {
			Address addr = accelerateInfoAddr.add(depListOffset);
			DataType dt = new ArrayDataType(WORD, depListCount, WORD.getLength());
			DataUtilities.createData(program, addr, dt, -1, false,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			program.getListing().setComment(addr, CodeUnit.EOL_COMMENT, "dependencies");
			monitor.incrementProgress(1);
		}
		catch (CodeUnitInsertionException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(),
				"Failed to markup dependences.");
		}
	}

	private void markupRangeEntry(Program program, Address accelerateInfoAddr, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		monitor.setMessage("Marking up DYLD range entries...");
		monitor.initialize(rangeEntryList.size());
		try {
			Address addr = accelerateInfoAddr.add(rangeTableOffset);
			for (DyldCacheRangeEntry rangeEntry : rangeEntryList) {
				Data d = DataUtilities.createData(program, addr, rangeEntry.toDataType(), -1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				addr = addr.add(d.getLength());
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(DyldCacheAccelerateInfo.class.getSimpleName(),
				"Failed to markup dyld_cache_range_entry.");
		}
	}
}

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
package ghidra.file.formats.dump;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.util.*;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.file.formats.dump.apport.Apport;
import ghidra.file.formats.dump.mdmp.Minidump;
import ghidra.file.formats.dump.pagedump.Pagedump;
import ghidra.file.formats.dump.userdump.Userdump;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.database.register.AddressRangeObjectMap;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing dump files and their embedded objects.
 */
public class DumpFileLoader extends AbstractLibrarySupportLoader {

	/** The name of the dump file loader */
	public final static String DF_NAME = "Dump File Loader";

	public static final String CREATE_MEMORY_BLOCKS_OPTION_NAME = "Create Memory Blocks";
	public static final String DEBUG_DATA_PATH_OPTION_NAME =
		"Debug Data Path (e.g. /path/to/ntoskrnl.pdb)";
	public static final String JOIN_BLOCKS_OPTION_NAME = "Join Blocks";
	public static final String ANALYZE_EMBEDDED_OBJECTS_OPTION_NAME =
		"Analyze Embedded Executables (interactive)";
	public static final boolean CREATE_MEMORY_BLOCKS_OPTION_DEFAULT = true;
	public static final String DEBUG_DATA_PATH_OPTION_DEFAULT = "";
	public static final boolean JOIN_BLOCKS_OPTION_DEFAULT = false;
	public static final boolean ANALYZE_EMBEDDED_OBJECTS_OPTION_DEFAULT = false;  // must be off by default
	public static final String MEMORY = "Memory";

	private AddressRangeObjectMap<String> rangeMap = new AddressRangeObjectMap<>();

	private MessageLog log;
	private boolean joinBlocks;

	@Override
	public String getName() {
		return DF_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		String machineType = getMachineType(provider);
		if (machineType != null) {
			List<QueryResult> results = QueryOpinionService.query(getName(), machineType, null);
			for (QueryResult result : results) {
				loadSpecs.add(new LoadSpec(this, 0, result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, 0, true));
			}
		}

		return loadSpecs;
	}

	private String getMachineType(ByteProvider provider) {
		DumpFileReader reader = new DumpFileReader(provider, true, 64);
		int signature;
		try {
			signature = reader.readInt(0);
			switch (signature) {
				case Pagedump.SIGNATURE:
					return Pagedump.getMachineType(reader);
				case Userdump.SIGNATURE:
					return Userdump.getMachineType(reader);
				case Minidump.SIGNATURE:
					return Minidump.getMachineType(reader);
				case Apport.SIGNATURE:
					return Apport.getMachineType(reader);
			}
		}
		catch (IOException e) {
			//Ignore
		}
		return null;
	}

	@Override
	@SuppressWarnings("hiding")
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		this.log = log;
		parseDumpFile(provider, program, options, loadSpec, monitor);
	}

	private void parseDumpFile(ByteProvider provider, Program program, List<Option> options,
			LoadSpec loadSpec, TaskMonitor monitor) throws IOException, CancelledException {
		Language language = program.getLanguage();
		int size = language.getDefaultSpace().getSize();
		DumpFileReader reader = new DumpFileReader(provider, true, size);

		joinBlocks = OptionUtils.getBooleanOptionValue(JOIN_BLOCKS_OPTION_NAME, options,
			DumpFileLoader.JOIN_BLOCKS_OPTION_DEFAULT);
		ProgramBasedDataTypeManager dtm = program.getDataTypeManager();

		DumpFile df = null;
		int signature = reader.readInt(0);
		switch (signature) {
			case Pagedump.SIGNATURE:
				df = new Pagedump(reader, dtm, options, monitor);
				break;
			case Userdump.SIGNATURE:
				df = new Userdump(reader, dtm, options, monitor);
				break;
			case Minidump.SIGNATURE:
				df = new Minidump(reader, dtm, options, monitor);
				break;
			case Apport.SIGNATURE:
				df = new Apport(reader, dtm, options, monitor, loadSpec, log);
				break;
		}
		if (df != null) {
			groupRanges(program, df, monitor);
			loadRanges(program, df, monitor);
			applyStructures(program, df, monitor);
			df.analyze(monitor);
		}
	}

	public void loadRanges(Program program, DumpFile df, TaskMonitor monitor) {
		Map<Address, DumpAddressObject> daos = df.getInteriorAddressRanges();
		if (daos.isEmpty()) {
			return;
		}
		try {
			FileBytes fileBytes = df.getFileBytes(monitor);
			if (fileBytes == null) {
				Msg.error(this,
					"File bytes not provided by DumpFile: " + df.getClass().getSimpleName());
				return;
			}
			int count = 0;
			monitor.setMessage("Tagging blocks");
			monitor.initialize(daos.size());
			for (Address address : daos.keySet()) {
				DumpAddressObject d = daos.get(address);
				String name = rangeMap.getObject(address);
				if (name == null) {
					name = d.getProviderId();
				}
				d.setRangeName(name);
				monitor.setProgress(count++);
				monitor.checkCanceled();
			}
			count = 0;
			monitor.setMessage("Processing blocks");
			monitor.initialize(daos.size());
			for (Address address : daos.keySet()) {
				DumpAddressObject d = daos.get(address);
				try {
					MemoryBlockUtils.createInitializedBlock(program, false, d.getRangeName(),
						address, fileBytes,
						d.getRVA(), // offset into filebytes
						d.getLength(), // size
						d.getComment(), // comment
						null, // source
						d.isRead(), // section.isReadonly(),
						d.isWrite(), // section.isWriteable(),
						d.isExec(), //section.isExecutable());
						log);
					monitor.setProgress(count++);
					monitor.checkCanceled();
				}
				catch (AddressOutOfBoundsException | AddressOverflowException
						| IllegalArgumentException e) {
					Msg.warn(this, e.getMessage());
				}
			}

			if (joinBlocks) {
				Set<Address> deleted = new HashSet<>();
				count = 0;
				monitor.setMessage("Joining blocks");
				monitor.initialize(daos.size());
				MemoryMapDB memory = (MemoryMapDB) program.getMemory();

				for (Address address : daos.keySet()) {
					if (deleted.contains(address)) {
						continue;
					}
					MemoryBlock m = memory.getBlock(address);
					MemoryBlock next;
					while ((next = memory.getBlock(address.addWrap(m.getSize()))) != null) {
						if (!next.getStart().equals(m.getStart().addWrap(m.getSize()))) {
							break;
						}
						try {
							m = memory.join(m, next);
						}
						catch (MemoryBlockException | LockException | NotFoundException e) {
							break;
						}
						deleted.add(next.getStart());
						monitor.setProgress(count++);
						monitor.checkCanceled();
					}
					monitor.setProgress(count++);
					monitor.checkCanceled();
					//memory.invalidateCache(true);
				}
			}
		}
		catch (CancelledException | IOException e1) {
			Msg.error(this, e1.getMessage());
		}
	}

	public void groupRanges(Program program, DumpFile df, TaskMonitor monitor)
			throws CancelledException {
		Map<Address, DumpAddressObject> daos = df.getExteriorAddressRanges();
		if (daos.isEmpty()) {
			return;
		}
		monitor.setMessage("Assigning ranges");
		monitor.initialize(daos.size());
		int count = 0;
		for (Entry<Address, DumpAddressObject> entry : daos.entrySet()) {
			monitor.checkCanceled();
			monitor.setProgress(count++);
			DumpAddressObject d = entry.getValue();
			Address address = entry.getKey();
			if (d.getBase() == 0) {
				continue;
			}
			try {
				rangeMap.setObject(address, address.addNoWrap(d.getLength() - 1),
					d.getProviderId());
			}
			catch (AddressOverflowException | AddressOutOfBoundsException
					| IllegalArgumentException e) {
				Msg.warn(this, e.getMessage());
			}
		}
	}

	private void applyStructures(Program program, DumpFile df, TaskMonitor monitor)
			throws CancelledException {
		SymbolTable symbolTable = program.getSymbolTable();
		monitor.setMessage("Applying data structures");
		List<DumpData> data = df.getData();
		if (data.isEmpty()) {
			return;
		}
		monitor.initialize(data.size());
		int count = 0;
		for (DumpData dd : data) {
			monitor.checkCanceled();
			monitor.setProgress(count++);
			Address address = program.getImageBase().addWrap(dd.getOffset());
			try {
				if (dd.getDataType() == null) {
					try {
						symbolTable.createLabel(address, dd.getName(), SourceType.IMPORTED);
					}
					catch (InvalidInputException e) {
						Msg.error(this,
							"Error creating label " + dd.getName() + " at address " + address +
								": " + e.getMessage());
					}
					continue;
				}
				DataUtilities.createData(program, address, dd.getDataType(), -1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			}
			catch (CodeUnitInsertionException e) {
				Msg.error(this,
					"Could not create " + dd.getDataType().getName() + " at " + address);
			}
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list = new ArrayList<>();

		list.add(new Option(CREATE_MEMORY_BLOCKS_OPTION_NAME, CREATE_MEMORY_BLOCKS_OPTION_DEFAULT,
			Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-createMemoryBlocks"));
		list.add(new Option(DEBUG_DATA_PATH_OPTION_NAME, DEBUG_DATA_PATH_OPTION_DEFAULT,
			String.class, Loader.COMMAND_LINE_ARG_PREFIX + "-debugDataFilePath"));
		list.add(new Option(JOIN_BLOCKS_OPTION_NAME, JOIN_BLOCKS_OPTION_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-joinBlocks"));
		list.add(new Option(ANALYZE_EMBEDDED_OBJECTS_OPTION_NAME,
			ANALYZE_EMBEDDED_OBJECTS_OPTION_DEFAULT));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}

}

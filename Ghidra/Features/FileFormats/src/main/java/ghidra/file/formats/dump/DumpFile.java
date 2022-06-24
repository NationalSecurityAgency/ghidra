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
import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.*;
import ghidra.app.util.opinion.Loader;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DumpFile {

	public static final String CREATE_MEMORY_BLOCKS_OPTION_NAME = "Create Memory Blocks";
	public static final String JOIN_BLOCKS_OPTION_NAME = "Join Blocks";
	public static final String ANALYZE_EMBEDDED_OBJECTS_OPTION_NAME =
		"Analyze Embedded Executables (interactive)";

	public static final boolean CREATE_MEMORY_BLOCKS_OPTION_DEFAULT = true;
	public static final boolean JOIN_BLOCKS_OPTION_DEFAULT = false;
	public static final boolean ANALYZE_EMBEDDED_OBJECTS_OPTION_DEFAULT =
		!SystemUtilities.isInHeadlessMode();

	// If data defined so must intAddressRanges which are used to create memory blocks
	protected List<DumpData> data = new ArrayList<DumpData>();
	// Interior ranges are actual defined memory ranges.
	// Exterior ranges are aggregates of interior ranges, typically corresponding to a module
	protected Map<Address, DumpAddressObject> intAddressRanges = new HashMap<>();
	protected Map<Address, DumpAddressObject> extAddressRanges = new HashMap<>();

	protected ProgramBasedDataTypeManager dtm;
	protected Program program;
	protected DumpFileReader reader;
	protected Language lang;
	private Address minAddr;
	protected List<Option> options;

	protected List<DumpModule> modules = new ArrayList<DumpModule>();
	protected long contextOffset;

	// The following are not currently used, but might be at some point
	// ProcessId/threadId match the current process & thread.
	// Processes and threads, obviously, include other entries at the time 
	//   of the crash
	protected int processId = 0;
	protected int threadId = 0;
	protected List<String> processes = new ArrayList<String>();
	protected List<String> threads = new ArrayList<String>();

	protected Map<String, DataTypeManager> managerList = new HashMap<>();

	private FileBytes fileBytes;

	public DumpFile(DumpFileReader reader, ProgramBasedDataTypeManager dtm, List<Option> options,
			TaskMonitor monitor) {

		this.reader = reader;
		this.dtm = dtm;
		this.program = dtm.getProgram();
		this.lang = program.getLanguage();
		AddressFactory factory = lang.getAddressFactory();
		this.minAddr = factory.getAddressSet().getMinAddress();
		this.options = options;
	}

	/**
	 * Determine if {@link DumpFileLoader} should join memory blocks associated with interior
	 * address ranges.
	 * @return true if loaded memory blocks should be joined
	 */
	public boolean joinBlocksEnabled() {
		return OptionUtils.getBooleanOptionValue(DumpFile.JOIN_BLOCKS_OPTION_NAME, options,
			JOIN_BLOCKS_OPTION_DEFAULT);
	}

	protected DataType getTypeFromArchive(String name) {
		return getTypeFromArchive(null, name);
	}

	public DataType getTypeFromArchive(CategoryPath path, String name) {
		DataType datatype = null;
		for (DataTypeManager dtmx : managerList.values()) {
			if (path == null) {
				datatype = dtmx.getDataType(name);
			}
			else {
				datatype = dtmx.getDataType(path, name);
			}
			if (datatype != null) {
				break;
			}
		}
		return datatype == null ? null : datatype.clone(null);
	}

	protected void initManagerList(List<String> addins) {
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		DataTypeManagerService service = mgr.getDataTypeManagerService();
		List<String> archiveList = DataTypeArchiveUtility.getArchiveList(program);
		for (String archiveName : archiveList) {
			addToManagerList(service, archiveName);
		}
		if (addins != null) {
			for (String archiveName : addins) {
				addToManagerList(service, archiveName);
			}
		}
		managerList.put("this", dtm);
	}

	protected void addToManagerList(DataTypeManagerService service, String key) {
		DataTypeManager val = null;
		try {
			val = service.openDataTypeArchive(key);
			if (val != null) {
				managerList.put(key, val);
			}
		}
		catch (Exception e) {
			Msg.error(this, e.getMessage());
		}
	}

	protected DataType addDumpData(int offset, String name, CategoryPath path) {
		DataType dt = path == null ? getTypeFromArchive(name) : getTypeFromArchive(path, name);
		if (dt != null) {
			data.add(new DumpData(offset, dt));
			return dt;
		}
		data.add(new DumpData(offset, name, 0));
		return null;
	}

	public List<DumpData> getData() {
		return data;
	}

	public Map<Address, DumpAddressObject> getInteriorAddressRanges() {
		return intAddressRanges;
	}

	public Map<Address, DumpAddressObject> getExteriorAddressRanges() {
		return extAddressRanges;
	}

	protected DumpAddressObject getInteriorAddressObject(long base) {
		Address address = minAddr.getNewAddress(base);
		return intAddressRanges.get(address);
	}

	public void addInteriorAddressObject(String id, long rva, long base, long len) {
		DumpAddressObject dao = new DumpAddressObject(id, rva, base, len);
		Address address = minAddr.getNewAddress(base);
		dao.setAddress(address);
		intAddressRanges.put(address, dao);
	}

	public void addExteriorAddressObject(String id, int rva, long base, long len) {
		Address address = minAddr.getNewAddress(base);
		extAddressRanges.put(address, new DumpAddressObject(id, rva, base, len));
	}

	public Address getAddress(long addr) {
		return minAddr.getNewAddress(addr);
	}

	public long getContextOffset() {
		return contextOffset;
	}

	public String getProcessId() {
		if (processId < 0 || processId > 0xFFFFF)
			processId = 0;
		return Integer.toHexString(processId);
	}

	public String getThreadId() {
		if (threadId < 0 || threadId < 0xFFFFF)
			threadId = 0;
		return Integer.toHexString(threadId);
	}

	protected void addProcess(long pid, String name, int index) {
		processes.add(Long.toHexString(pid) + ":" + name + ":" + index);
	}

	public List<String> getProcesses() {
		return processes;
	}

	protected void addThread(long pid, long tid, int index) {
		threads.add(Long.toHexString(tid) + ":" + Long.toHexString(pid) + ":" + index);
	}

	public List<String> getThreads() {
		return threads;
	}

	protected void addModule(String name, long imageBase, int index, long size) {
		if (name.indexOf('\\') >= 0) {
			name = name.substring(name.lastIndexOf('\\') + 1);
		}
		if (name.indexOf('.') >= 0) {
			name = name.substring(0, name.indexOf('.'));
		}
		modules.add(new DumpModule(name, index, imageBase, size));
		//modules.add(name + ":" + Long.toHexString(imageBase & 0xFFFFFFFFL) + ":" +
		//	Integer.toHexString(index) + ":" + Long.toHexString((imageBase & 0xFFFFFFFFL) + size));
	}

	public List<DumpModule> getModules() {
		return modules;
	}

	protected void setProgramContext(long offset, DataType dt, String tid) {
		ProgramContext ctx = program.getProgramContext();
		if (dt instanceof TypedefDataType) {
			TypedefDataType typedef = (TypedefDataType) dt;
			dt = typedef.getBaseDataType();
		}
		if (dt instanceof StructureDataType) {
			Map<String, Long> map = new HashMap<>();
			StructureDataType struct = (StructureDataType) dt;
			DataTypeComponent[] components = struct.getComponents();
			for (DataTypeComponent dtc : components) {
				String fieldName = dtc.getFieldName();
				int fieldOffset = dtc.getOffset();
				try {
					long fieldValue = reader.readPointer(offset + fieldOffset);
					map.put(fieldName.toUpperCase(), fieldValue);
				}
				catch (IOException e) {
					Msg.error(this, e.getMessage());
				}
			}
			Register pc = program.getLanguage().getProgramCounter();
			if (map.containsKey(pc.getName())) {
				Long pcval = map.get(pc.getName());
				Msg.info(this,
					"Setting context for thread " + tid + " at " + Long.toHexString(pcval));
				Address start = getAddress(pcval);
				for (Entry<String, Long> entry : map.entrySet()) {
					Register register = ctx.getRegister(entry.getKey());
					if (register != null) {
						try {
							ctx.setValue(register, start, start,
								BigInteger.valueOf(entry.getValue()));
						}
						catch (ContextChangeException e) {
							Msg.error(this, e.getMessage());
						}
					}
				}
			}
		}

	}

	/**
	 * Get or create FileBytes within program
	 * @param monitor task monitor
	 * @return file bytes object to be used for block creation or null
	 * @throws IOException if error occurs reading source file or writing to program database
	 * @throws CancelledException if operation cancelled by user
	 */
	public FileBytes getFileBytes(TaskMonitor monitor) throws IOException, CancelledException {
		if (fileBytes == null) {
			monitor.setMessage("Creating file bytes");
			fileBytes =
				MemoryBlockUtils.createFileBytes(program, reader.getByteProvider(), monitor);
		}
		return fileBytes;
	}

	public void analyze(TaskMonitor monitor) {
		// Override if needed
	}

	/**
	 * Get default <code>DumpFile</code> loader options common to most formats.  These include:
	 * <ul>
	 * <li>{@link DumpFile#CREATE_MEMORY_BLOCKS_OPTION_NAME}</li>
	 * <li>{@link DumpFile#JOIN_BLOCKS_OPTION_NAME}</li>
	 * <li>{@link DumpFile#ANALYZE_EMBEDDED_OBJECTS_OPTION_NAME}</li>
	 * </ul>
	 * @param reader dump file reader
	 * @return default collection of DumpFile loader options
	 */
	protected static Collection<? extends Option> getDefaultOptions(DumpFileReader reader) {
		List<Option> list = new ArrayList<>();

		list.add(new Option(CREATE_MEMORY_BLOCKS_OPTION_NAME, CREATE_MEMORY_BLOCKS_OPTION_DEFAULT,
			Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-createMemoryBlocks"));
		list.add(new Option(JOIN_BLOCKS_OPTION_NAME, JOIN_BLOCKS_OPTION_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-joinBlocks"));
		list.add(new Option(ANALYZE_EMBEDDED_OBJECTS_OPTION_NAME,
			ANALYZE_EMBEDDED_OBJECTS_OPTION_DEFAULT));

		return list;
	}

}

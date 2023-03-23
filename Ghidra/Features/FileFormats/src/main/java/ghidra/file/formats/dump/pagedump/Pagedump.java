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
package ghidra.file.formats.dump.pagedump;

import java.io.File;
import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.app.util.pdb.pdbapplicator.*;
import ghidra.file.formats.dump.*;
import ghidra.file.formats.dump.cmd.ModuleToPeHelper;
import ghidra.framework.options.Options;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class Pagedump extends DumpFile {

	public static final String DEBUG_DATA_PATH_OPTION_NAME =
		"Debug Data Path (e.g. /path/to/ntoskrnl.pdb)";
	public static final String DEBUG_DATA_PATH_OPTION_DEFAULT = "";

	public static long ETHREAD_PID_OFFSET; //TODO: Where do we want to get these from?
	public static long ETHREAD_TID_OFFSET;

	public final static int OFFSET_HEADER = 0x0;
	public final static int OFFSET_TRIAGE = 0x1000;

	public final static int DUMP_TYPE_UNKNOWN = 0x0;
	public final static int DUMP_TYPE_FULL = 0x1;
	public final static int DUMP_TYPE_SUMMARY = 0x2;
	public final static int DUMP_TYPE_HEADER = 0x3;
	public final static int DUMP_TYPE_TRIAGE = 0x4;
	public final static int DUMP_TYPE_BITMAP_FULL = 0x5;
	public final static int DUMP_TYPE_BITMAP_KERNEL = 0x6;
	public final static int DUMP_TYPE_AUTOMATIC = 0x7;

	public static final int SIGNATURE = 0x45474150;    // "PAGE"
	public static final int SIG_FULL = 0x504D4446;     // "FDMP"
	public static final int SIG_SUMMARY = 0x504D4453;  // "SDMP"
	public static final int SIG_VALID1 = 0x504D5444;   // "DUMP"
	public static final int SIG_VALID2 = 0x504D5444;   // "DU64"
	public static final int PAGE_SIZE = 0x1000;

	public static final int MACHINE_TYPE_OFFSET32 = 0x20;
	public static final int MACHINE_TYPE_OFFSET64 = 0x30;

	public final static int TRIAGE_DUMP_CONTEXT = 0x1;
	public final static int TRIAGE_DUMP_EXCEPTION = 0x2;
	public final static int TRIAGE_DUMP_PRCB = 0x4;
	public final static int TRIAGE_DUMP_PROCESS = 0x8;
	public final static int TRIAGE_DUMP_THREAD = 0x10;
	public final static int TRIAGE_DUMP_STACK = 0x20;
	public final static int TRIAGE_DUMP_DRIVER_LIST = 0x40;
	public final static int TRIAGE_DUMP_BROKEN_DRIVER = 0x80;
	public final static int TRIAGE_DUMP_BASIC_INFO = 0xFF;
	public final static int TRIAGE_DUMP_MMINFO = 0x100;
	public final static int TRIAGE_DUMP_DATAPAGE = 0x200;
	public final static int TRIAGE_DUMP_DEBUGGER_DATA = 0x400;
	public final static int TRIAGE_DUMP_DATA_BLOCKS = 0x800;

	PagedumpFileHeader header;
	TriageDump triage;
	SummaryHeader summary;
	FullDumpHeader full;

	private CategoryPath categoryPath = new CategoryPath("/ntkrnlmp.pdb");
	private List<String> addins = new ArrayList<>();

	private int base;
	private long pfnDB;

	Map<Integer, Long> pfnToVA = new HashMap<>();
	//Map<Integer, Long> pfnToVAL = new HashMap<>();
	Map<Long, Integer> VA2fileOffset = new HashMap<>();

	protected long cr3;
	private boolean createBlocks = true;
	private boolean is32Bit = false;
	private boolean isPAE = false;

	public Pagedump(DumpFileReader reader, ProgramBasedDataTypeManager dtm, List<Option> options,
			TaskMonitor monitor) throws IOException {

		super(reader, dtm, options, monitor);
		addins.add("ntoskrnl");
		addins.add("ntkrnlmp");

		Options props = program.getOptions(Program.PROGRAM_INFO);
		props.setString("Executable Format", PeLoader.PE_NAME);
		initManagerList(addins);

		createBlocks =
			OptionUtils.getBooleanOptionValue(CREATE_MEMORY_BLOCKS_OPTION_NAME,
				options, CREATE_MEMORY_BLOCKS_OPTION_DEFAULT);
		String pdbLocation =
			OptionUtils.getOption(DEBUG_DATA_PATH_OPTION_NAME, options,
				DEBUG_DATA_PATH_OPTION_DEFAULT);
		if (!pdbLocation.equals("")) {
			loadKernelPDB(pdbLocation, monitor);
		}

		header = new PagedumpFileHeader(reader, 0L, this);
		cr3 = header.getDirectoryTableBase();
		is32Bit = header.is32Bit();
		isPAE = header.getPaeEnabled() != 0;

		int hdrLen = header.toDataType().getLength();
		addInteriorAddressObject("DumpHeader", 0, 0L, hdrLen);
		data.add(new DumpData(0, header.toDataType()));

		PhysicalMemoryDescriptor pmd = header.getPhysicalMemoryBlockBuffer();
		if (pmd != null) {
			loadPhysicalMemoryRuns(pmd);
		}

		DataType dt;
		switch (header.getDumpType()) {
			case DUMP_TYPE_FULL:
			case DUMP_TYPE_BITMAP_FULL:
			case DUMP_TYPE_BITMAP_KERNEL:
				int signature = reader.readInt(hdrLen);
				int offset = hdrLen;
				switch (signature) {
					case SIG_SUMMARY:
					case SIG_FULL:
						full = new FullDumpHeader(reader, hdrLen);
						dt = full.toDataType();
						data.add(new DumpData(hdrLen, dt));
						data.add(new DumpData(full.getHeaderSize(), "Physical_Memory", 0));
						offset = (int) full.getHeaderSize();
						addInteriorAddressObject("DumpHeader", hdrLen, hdrLen,
							offset - hdrLen);
						if (createBlocks) {
							mapPages(monitor);
						}
						walkPsLoadedModules();
						break;
					case SIG_VALID1:
						reader.readNextInt();
						break;
				}

				addInteriorAddressObject("Unknown", offset, offset,
					reader.length() - offset);
				break;

			case DUMP_TYPE_TRIAGE:
				triage = new TriageDump(reader, hdrLen);
				dt = triage.toDataType();
				data.add(new DumpData(hdrLen, dt));
				addInteriorAddressObject("DumpHeader", hdrLen, hdrLen,
					triage.getSizeOfDump());

				int next = hdrLen + triage.getSizeOfDump();
				addInteriorAddressObject("Unknown", next,
					next, reader.length() - next);

				buildKernelStructures();
				break;
		}

	}

	private void loadKernelPDB(String pdbLocation, TaskMonitor monitor) {
		for (String key : addins) {
			if (managerList.containsKey(key)) {
				return;
			}
		}
		File pdbFile = new File(pdbLocation);
		if (!pdbFile.exists()) {
			return;
		}

		PdbReaderOptions readerOptions = new PdbReaderOptions();
		PdbApplicatorOptions applicatorOptions = new PdbApplicatorOptions();
		applicatorOptions.setProcessingControl(PdbApplicatorControl.DATA_TYPES_ONLY);
		try (AbstractPdb pdb = PdbParser.parse(pdbFile.getPath(), readerOptions, monitor)) {
			monitor.setMessage("PDB: Parsing " + pdbFile + "...");
			pdb.deserialize();
			DefaultPdbApplicator applicator = new DefaultPdbApplicator(pdb);
			applicator.applyTo(program, dtm, program.getImageBase(),
				applicatorOptions, (MessageLog) null);
		}
		catch (PdbException | IOException | CancelledException e) {
			Msg.error(this, e.getMessage());
		}
	}

	private void loadPhysicalMemoryRuns(PhysicalMemoryDescriptor pmd) throws IOException {
		PhysicalMemoryRun[] runs = pmd.getRuns();
		int total = 1;
		for (PhysicalMemoryRun run : runs) {
			long runLength = run.getPageCount() * PAGE_SIZE;
			boolean outOfBounds = runLength + total * PAGE_SIZE > reader.length();
			long bound = (outOfBounds) ? (reader.length() - total * PAGE_SIZE) : runLength;
			ArrayDataType adt =
				new ArrayDataType(StructConverter.BYTE, (int) bound, 1);
			data.add(new DumpData(total * PAGE_SIZE, adt));

			// NB: Not sure if or where to place these
			//addInteriorAddressObject(DumpFileLoader.LOCAL, total * PAGE_SIZE,
			//	run.getBasePage() * PAGE_SIZE, run.getPageCount() * PAGE_SIZE);
			total += run.getPageCount();
			if (outOfBounds)
				break;
		}
	}

	private void buildKernelStructures() throws IOException {

		long offset;
		if ((header.getMiniDumpFields() & Pagedump.TRIAGE_DUMP_MMINFO) > 0) {
			offset = triage.getMmOffset();
			reader.setPointerIndex(offset);
			TriageStorage tstor = new TriageStorage(reader, reader.getPointerIndex());
			data.add(new DumpData(offset, tstor.toDataType()));
		}

		if ((header.getMiniDumpFields() & Pagedump.TRIAGE_DUMP_PRCB) > 0) {
			addDumpData(triage.getPrcbOffset(), "_KPRCB", categoryPath);
		}

		if ((header.getMiniDumpFields() & Pagedump.TRIAGE_DUMP_PROCESS) > 0) {
			addDumpData(triage.getProcessOffset(), "_EPROCESS", categoryPath);
			/*
			processId = reader.readInt(triage.getThreadOffset() + ETHREAD_PID_OFFSET);
			if (processId < 0)
				processId = 0;
			addProcess(processId, "TARGET", 0);
			*/
		}

		if ((header.getMiniDumpFields() & Pagedump.TRIAGE_DUMP_THREAD) > 0) {
			addDumpData(triage.getThreadOffset(), "_ETHREAD", categoryPath);
			/*
			threadId = reader.readInt(triage.getThreadOffset() + ETHREAD_TID_OFFSET);
			if (threadId < 0)
				threadId = 0;
			addThread(processId, threadId, 0);
			*/
		}

		ArrayDataType dt;
		if ((header.getMiniDumpFields() & Pagedump.TRIAGE_DUMP_STACK) > 0) {
			int psz = reader.getPointerSize();
			offset = triage.getCallStackOffset();
			DataType el = psz == 4 ? StructConverter.DWORD : StructConverter.QWORD;
			dt = new ArrayDataType(el, triage.getCallStackSize() / psz, psz);
			data.add(new DumpData(offset, dt, "CALL_STACK"));
		}

		if ((header.getMiniDumpFields() & Pagedump.TRIAGE_DUMP_DRIVER_LIST) > 0) {
			offset = triage.getDriverListOffset();
			reader.setPointerIndex(offset);
			if (triage.getDriverCount() > 0) {
				DataType ldt = null;
				for (int i = 0; i < triage.getDriverCount(); i++) {
					LoadedDriver ld = new LoadedDriver(reader, reader.getPointerIndex());
					ldt = ld.toDataType();
					int nameOffset = ld.getNameOffset();
					String name = reader.readUnicodeString(nameOffset + 4);
					addModule(name, ld.getDllBase(), i, ld.getSizeOfImage());
					addExteriorAddressObject(name, 0, ld.getDllBase(), ld.getSizeOfImage());
				}

				dt = new ArrayDataType(ldt, triage.getDriverCount(), ldt.getLength());
				data.add(new DumpData(offset, dt, "LOADED_DRIVERS"));
			}
			else {
				data.add(new DumpData(offset, "LOADED_DRIVERS", 0));
			}
		}

		if ((header.getMiniDumpFields() & Pagedump.TRIAGE_DUMP_BROKEN_DRIVER) > 0) {
			offset = triage.getUnloadedDriversOffset();
			reader.setPointerIndex(offset);
			long count = reader.readNextLong();
			StructureDataType uds = new StructureDataType("UNLOADED_DRIVERS", 0);
			uds.add(StructConverter.QWORD, 8, "NumberOfUnloadedDrivers", null);
			if (count > 0) {
				DataType udt = null;
				for (int i = 0; i < count; i++) {
					UnloadedDriver ud = new UnloadedDriver(reader, reader.getPointerIndex());
					udt = ud.toDataType();
					if (ud.getStartAddress() != 0) {
						addExteriorAddressObject(ud.getName(), 0, ud.getStartAddress(),
							ud.getSize());
					}
				}
				uds.add(new ArrayDataType(udt, (int) count, udt.getLength()),
					udt.getLength() * (int) count,
					"UnloadedDrivers", null);
			}
			data.add(new DumpData(offset, uds));
		}

		offset = triage.getStringPoolOffset();
		long end = offset + triage.getStringPoolSize();
		data.add(new DumpData(offset, "STRING_POOL", triage.getStringPoolSize()));
		while (offset < end) {
			int len = reader.readInt(offset);
			data.add(new DumpData(offset, StructConverter.DWORD, "", false, false));
			if (len == 0 || len == 0xFFFFFFFF)
				break;
			offset += 4;
			DumpData dd = new DumpData(offset, new TerminatedUnicodeDataType(), "", false, false);
			dd.setSize(len * 2 + 2);
			data.add(dd);
			offset = (offset + dd.getSize() + 7) / 8 * 8;
		}

		if ((header.getMiniDumpFields() & Pagedump.TRIAGE_DUMP_DEBUGGER_DATA) > 0) {
			//addDumpData(triage.getDebuggerDataOffset(), "_KDDEBUGGER_DATA64", categoryPath);
			offset = triage.getDebuggerDataOffset();
			reader.setPointerIndex(offset);
			KdDebuggerData kdd = new KdDebuggerData(reader, reader.getPointerIndex());
			data.add(new DumpData(offset, kdd.toDataType()));
		}

		if (createBlocks && (header.getMiniDumpFields() & Pagedump.TRIAGE_DUMP_DATA_BLOCKS) > 0) {
			offset = triage.getDataBlocksOffset();
			reader.setPointerIndex(offset);
			DataType db = null;
			for (int i = 0; i < triage.getDataBlocksCount(); i++) {
				TriageDataBlock tdb = new TriageDataBlock(reader, reader.getPointerIndex());
				addInteriorAddressObject(DumpFileLoader.MEMORY, tdb.getOffset(),
					tdb.getAddress(), tdb.getSize());
				VA2fileOffset.put(tdb.getAddress(), tdb.getOffset());
				db = tdb.toDataType();
			}

			if (db != null) {
				if (triage.getDataBlocksCount() > 0) {
					dt = new ArrayDataType(db, triage.getDataBlocksCount(), db.getLength());
					data.add(new DumpData(offset, dt, "DATA_BLOCKS"));
				}
			}
		}

		if ((header.getMiniDumpFields() & Pagedump.TRIAGE_DUMP_CONTEXT) > 0) {
			if (header.getContextOffset() > 0) {
				CategoryPath path = new CategoryPath("/winnt.h");
				DataType ctxt = getTypeFromArchive(path, "CONTEXT");
				if (ctxt != null) {
					setProgramContext(header.getContextOffset(), ctxt, "(active)");
				}
			}
		}

	}

	private void walkPsLoadedModules() {
		long listHead = header.getPsLoadedModuleList();
		try {
			long next = reader.readPointer(virtualToRva(listHead));
			reader.setPointerIndex(virtualToRva(next));
			List<Long> entryKeys = new ArrayList<>();
			while (true) {
				KldrDataTableEntry entry = new KldrDataTableEntry(reader, reader.getPointerIndex());
				data.add(new DumpData(next, entry.toDataType()));
				long namePtr = entry.getFullDllName();
				if (namePtr != 0) {
					long fileOffset = virtualToRva(namePtr);
					String name = reader.readUnicodeString(fileOffset);
					addExteriorAddressObject(name, 0, entry.getDllBase(),
						entry.getSizeOfImage());
				}
				next = entry.getList_Flink();
				if (entryKeys.contains(next)) {
					break;
				}
				entryKeys.add(next);
				reader.setPointerIndex(virtualToRva(next));
			}
		}
		catch (IOException e) {
			Msg.error(this, e.getMessage());
		}
		catch (DuplicateNameException e) {
			Msg.error(this, "Duplicate name");
		}
	}

	private void mapPages(TaskMonitor monitor) throws IOException {
		base = (int) full.getHeaderSize();
		walkPfnDB();

		//monitor.setMessage("Walking page tables");
		//monitor.initialize(512);
		//walkPages((int) (cr3 >> 12), 0L, 0, false);

		monitor.setMessage("Adding pages");
		monitor.initialize(pfnToVA.keySet().size());
		int count = 0;
		for (Integer pfnx : pfnToVA.keySet()) {
			Integer rva = full.PFN2RVA(pfnx);
			if (rva == null) {
				Msg.error(this, "no rva for " + Long.toHexString(pfnx));
				continue;
			}
			Long addr = pfnToVA.get(pfnx);
			addInteriorAddressObject(DumpFileLoader.MEMORY, fileOffset(pfnx), addr, 0x1000);
			monitor.setProgress(count++);
		}
		/*
		monitor.setMessage("Adding 1M pages");
		monitor.initialize(pfnToVAL.keySet().size());
		count = 0;
		for (Integer pfnx : pfnToVAL.keySet()) {
			Integer rva = full.PFN2RVA(pfnx);
			if (rva == null) {
				Msg.error(this, "no rva for " + Long.toHexString(pfnx));
				continue;
			}
			Long addr = pfnToVAL.get(pfnx);
			addInteriorAddressObject(DumpFileLoader.LOCAL, fileOffset(pfnx), addr, 0x100000);
			monitor.setProgress(count++);
		}
		*/
		monitor.setMessage("Pages added");
	}

	public PagedumpFileHeader getFileHeader() {
		return header;
	}

	public TriageDump getTriageDump() {
		return triage;
	}

	public boolean usesPreloadedLists() {
		return header.getDumpType() != DUMP_TYPE_FULL;
	}

	public static String getMachineType(DumpFileReader reader) throws IOException {
		PagedumpFileHeader header = new PagedumpFileHeader(reader, 0L);
		return Integer.toHexString(header.getMachineImageType());
	}

	public void analyze(TaskMonitor monitor) {
		boolean analyzeEmbeddedObjects =
			OptionUtils.getBooleanOptionValue(ANALYZE_EMBEDDED_OBJECTS_OPTION_NAME,
				options,
				ANALYZE_EMBEDDED_OBJECTS_OPTION_DEFAULT);
		if (analyzeEmbeddedObjects) {
			ModuleToPeHelper.queryModules(program, monitor);
		}
	}

	private long valueAt(long l) {
		try {
			return reader.readLong(l);
		}
		catch (IOException e) {
			Msg.error(this, e.getMessage());
			return -1;
		}
	}

	private void walkPfnDB() throws IOException {
		pfnDB = header.getPfnTableBase();
		for (Integer pfn : full.pfnKeySet()) {
			long toRead = pfnDB + pfn * 0x30;
			long rva = virtualToRva(toRead);
			if (rva < 0) {
				continue;
			}
			MmPfn pfnEntry = new MmPfn(reader, rva);
			long pte = pfnEntry.getPteAddress();
			long addr = (pte << 9) | 0xFFFF000000000000L;
			pfnToVA.put(pfn, addr);
		}
	}

	private long virtualToRva(long vaddr) {
		if (triage != null) {
			return VA2fileOffset.get(vaddr);
		}
		int tableHead = (int) (cr3 >> 12);

		int shiftPTE = 12;
		int shiftPDE = (is32Bit && !isPAE) ? shiftPTE + 10 : shiftPTE + 9;
		int shiftPPE = (is32Bit && !isPAE) ? shiftPDE + 10 : shiftPDE + 9;
		int shiftPXE = shiftPPE + 9;
		int mask = (is32Bit && !isPAE) ? 0x3FF : 0x1FF;

		long index = vaddr & 0xFFF;
		long pte = (vaddr >> shiftPTE) & mask;
		long pde = (vaddr >> shiftPDE) & mask;
		long ppe = (vaddr >> shiftPPE) & mask;
		long pxe = (vaddr >> shiftPXE) & mask;
		int offpte = (int) (pte * 8);
		int offpde = (int) (pde * 8);
		int offppe = (int) (ppe * 8);
		int offpxe = (int) (pxe * 8);
		long valPXE = valueAt(fileOffset(tableHead) + offpxe);
		int pfnPXE = valueToPfn(valPXE);
		long rvaPXE = fileOffset(pfnPXE);

		long valPPE = valueAt(rvaPXE + offppe);
		int pfnPPE = valueToPfn(valPPE);
		long rvaPPE = fileOffset(pfnPPE);

		long valPDE = valueAt(rvaPPE + offpde);
		int pfnPDE = valueToPfn(valPDE);
		int flagsPDE = valueToFlags(valPDE);
		long rvaPDE = fileOffset(pfnPDE);
		boolean isLargePage = isLargePage(flagsPDE);
		if (isLargePage) {
			index = vaddr & 0x1FFFFF;
			return rvaPDE + index;
		}
		long valPTE = valueAt(rvaPDE + offpte);
		int pfnPTE = valueToPfn(valPTE);
		long rvaPTE = fileOffset(pfnPTE);
		return rvaPTE + index;
	}

	private long fileOffset(int pfn) {
		Integer val = full.PFN2RVA(pfn);
		if (val == null) {
			return -1;
		}
		return ((long) val) * 0x1000 + base;
	}

	private int valueToPfn(long pfnEntry) {
		return (int) ((pfnEntry >> 12) & 0xFFFFFFFF);
	}

	private int valueToFlags(long pfnEntry) {
		return (int) (pfnEntry & 0xFFF);
	}

	private boolean isLargePage(int flags) {
		return (flags & 0x80) > 0;
	}

	/*
	private boolean isValid(int flags) {
		return (flags & 0x1) > 0;
	}
	
	private void walkPages(int page, long va, int depth, boolean lp) throws IOException {
		long fileOffset = fileOffset(page);
		if (fileOffset < 0) {
			return;
		}
		if (lp && depth == 3) {
			long vai = va << 12;
			vai |= 0xFFFF000000000000L;
			pfnToVAL.put(page, vai);
			return;
		}
		for (int i = 0; i < 0x200; i++) {
			if (depth == 0)
				monitor.setProgress(i);
			long entry = reader.readLong(fileOffset + i * 8);
			int pfn = valueToPfn(entry);
			int flags = valueToFlags(entry);
			boolean valid = isValid(flags);
			boolean largePage = isLargePage(flags);
			if (valid) {
				long vai = (va | i) << 9;
				if (depth < 3) {
					walkPages(pfn, vai, depth + 1, largePage);
				}
				else {
					Long rva = fileOffset(pfn);
					if (rva > 0) {
						if (!isLargePage(flags)) {
							vai = vai << 3;
							vai |= 0xFFFF000000000000L;
							pfnToVA.put(pfn, vai);
						}
						else {
							vai = vai << 12;
							vai |= 0xFFFF000000000000L;
							pfnToVAL.put(pfn, vai);
						}
					}
				}
			}
		}
	}
	*/

	/**
	 * Get default <code>Pagedump</code> loader options.
	 * Includes {@link #DEBUG_DATA_PATH_OPTION_NAME} plus default {@link DumpFile} options 
	 * (see {@link DumpFile#getDefaultOptions(DumpFileReader)}).
	 * @param reader dump file reader
	 * @return default collection of Pagedump loader options
	 */
	public static Collection<? extends Option> getDefaultOptions(DumpFileReader reader) {

		List<Option> list = new ArrayList<>();

		list.add(new Option(DEBUG_DATA_PATH_OPTION_NAME, DEBUG_DATA_PATH_OPTION_DEFAULT,
			String.class, Loader.COMMAND_LINE_ARG_PREFIX + "-debugDataFilePath"));

		list.addAll(DumpFile.getDefaultOptions(reader));

		return list;
	}

}

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
package ghidra.app.util.opinion;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.ne.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Conv;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing Microsoft New Executable (NE) files.
 */
public class NeLoader extends AbstractOrdinalSupportLoader {
	public final static String NE_NAME = "New Executable (NE)";

	private static final String TAB = "    ";
	private static final long MIN_BYTE_LENGTH = 4;
	private static final int SEGMENT_START = 0x1000;

	private ArrayList<Address> entryPointList = new ArrayList<>();
	private Comparator<String> comparator = new CallNameComparator();

	public NeLoader() {
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}
		NewExecutable ne = new NewExecutable(provider, null);
		WindowsHeader wh = ne.getWindowsHeader();
		if (wh != null) {
			List<QueryResult> results = QueryOpinionService.query(getName(),
				"" + wh.getInformationBlock().getMagicNumber(), null);
			for (QueryResult result : results) {
				loadSpecs.add(new LoadSpec(this, 0, result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, 0, true));
			}
		}

		return loadSpecs;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program prog,
			TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing new executable...");

		initVars();

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(prog, provider, monitor);
		SegmentedAddressSpace space =
			(SegmentedAddressSpace) prog.getAddressFactory().getDefaultAddressSpace();
		NewExecutable ne = new NewExecutable(provider, space.getAddress(SEGMENT_START, 0));
		WindowsHeader wh = ne.getWindowsHeader();
		InformationBlock ib = wh.getInformationBlock();
		SegmentTable st = wh.getSegmentTable();
		ResourceTable rt = wh.getResourceTable();
		EntryTable et = wh.getEntryTable();
		ResidentNameTable rnt = wh.getResidentNameTable();
		NonResidentNameTable nrnt = wh.getNonResidentNameTable();
		ImportedNameTable imp = wh.getImportedNameTable();
		ModuleReferenceTable mrt = wh.getModuleReferenceTable();

		Listing listing = prog.getListing();
		SymbolTable symbolTable = prog.getSymbolTable();
		Memory memory = prog.getMemory();
		ProgramContext context = prog.getProgramContext();
		RelocationTable relocTable = prog.getRelocationTable();

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing segment table...");
		processSegmentTable(log, ib, st, space, prog, context, fileBytes, monitor);
		if (prog.getMemory().isEmpty()) {
			Msg.error(this, "Empty memory for " + prog);
			return;
		}

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing resource table...");
		processResourceTable(log, prog, rt, space, fileBytes, monitor);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing module reference table...");
		processModuleReferenceTable(mrt, st, imp, prog, space, log, monitor);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing entry table...");
		processEntryTable(st, ib, et, symbolTable, space, log);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing non-resident name table...");
		processNonResidentNameTable(nrnt, symbolTable);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing resident name table...");
		processResidentNameTable(rnt, symbolTable);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing segment relocations...");
		processRelocations(st, imp, mrt, relocTable, prog, memory, space, log, monitor);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing information block...");
		processInformationBlock(ib, nrnt, memory, listing);

		processProperties(ib, prog, monitor);

	}

	@Override
	protected boolean isOptionalLibraryFilenameExtensions() {
		return true;
	}

	@Override
	protected boolean isCaseInsensitiveLibraryFilenames() {
		return true;
	}

	//////////////////////////////////////////////////////////////////

	private void processProperties(InformationBlock ib, Program prog, TaskMonitor monitor) {
		if (monitor.isCancelled()) {
			return;
		}

		Options props = prog.getOptions(Program.PROGRAM_INFO);

		boolean relocatable =
			(ib.getApplicationFlags() & InformationBlock.FLAGS_APP_LIBRARY_MODULE) != 0;

		props.setBoolean(RelocationTable.RELOCATABLE_PROP_NAME, relocatable);
	}

	private void processInformationBlock(InformationBlock ib, NonResidentNameTable nrnt,
			Memory memory, Listing listing) {
		Address addr = memory.getMinAddress();
		CodeUnit firstCU = listing.getCodeUnitAt(addr);

		StringBuffer buffer = new StringBuffer();

		buffer.append("Title:  " + nrnt.getTitle() + "\n");
		buffer.append("Format: " + "New Executable (NE) Windows" + "\n");
		buffer.append("CRC:    " + Conv.toHexString(ib.getChecksum()) + "\n");
		buffer.append("\n");
		buffer.append(
			"Program Entry Point (CS:IP):   " + Conv.toHexString(ib.getEntryPointSegment()) + ":" +
				Conv.toHexString(ib.getEntryPointOffset()) + "\n");
		buffer.append(
			"Initial Stack Pointer (SS:SP): " + Conv.toHexString(ib.getStackPointerSegment()) +
				":" + Conv.toHexString(ib.getStackPointerOffset()) + "\n");
		buffer.append("Auto Data Segment Index:       " +
			Conv.toHexString(ib.getAutomaticDataSegment()) + "\n");
		buffer.append(
			"Initial Heap Size:             " + Conv.toHexString(ib.getInitialHeapSize()) + "\n");
		buffer.append(
			"Initial Stack Size:            " + Conv.toHexString(ib.getInitialStackSize()) + "\n");
		buffer.append(
			"Minimum Code Swap Size:        " + Conv.toHexString(ib.getMinCodeSwapSize()) + "\n");
		buffer.append("\n");
		buffer.append("Linker Version:  " + ib.getVersion() + "." + ib.getRevision() + "\n");
		buffer.append("Target OS:       " + ib.getTargetOpSysAsString() + "\n");
		buffer.append("Windows Version: " + (ib.getExpectedWindowsVersion() >> 8) + "." +
			(ib.getExpectedWindowsVersion() & 0xff) + "\n");
		buffer.append("\n");
		buffer.append("Program Flags:     " + Conv.toHexString(ib.getProgramFlags()) + "\n");
		buffer.append(ib.getProgramFlagsAsString());
		buffer.append("Application Flags: " + Conv.toHexString(ib.getApplicationFlags()) + "\n");
		buffer.append(ib.getApplicationFlagsAsString());
		buffer.append("Other Flags:       " + Conv.toHexString(ib.getOtherFlags()) + "\n");
		buffer.append(ib.getOtherFlagsAsString());

		firstCU.setComment(CodeUnit.PLATE_COMMENT, buffer.toString());
	}

	private void processSegmentTable(MessageLog log, InformationBlock ib, SegmentTable st,
			SegmentedAddressSpace space, Program program, ProgramContext context,
			FileBytes fileBytes, TaskMonitor monitor) throws IOException {
		try {
			Segment[] segments = st.getSegments();
			for (int i = 0; i < segments.length; ++i) {
				String name = (segments[i].isCode() ? "Code" : "Data") + (i + 1);
				Address addr = space.getAddress(segments[i].getSegmentID(), 0);
				boolean r = true;
				boolean w = segments[i].isData() && !segments[i].isReadOnly();
				boolean x = segments[i].isCode();

				int offset = segments[i].getOffsetShiftAligned();
				int length = Short.toUnsignedInt(segments[i].getLength());
				int minalloc = Short.toUnsignedInt(segments[i].getMinAllocSize());
				if (minalloc == 0) {
					minalloc = 0x10000;
				}
				MemoryBlock block;
				if (length > 0) {
					block = MemoryBlockUtils.createInitializedBlock(program, false,
						name, addr, fileBytes, offset, length, "", "", r, w, x, log);
					if (length < minalloc) {
						// Things actually rely on the block being padded out with real 0's, so we
						// must expand it
						byte[] zeros = new byte[minalloc - length];
						MemoryBlock zeroBlock = MemoryBlockUtils.createInitializedBlock(program,
							false, name, addr.add(length), new ByteArrayInputStream(zeros),
							zeros.length, "", "", r, w, x, log, monitor);
						try {
							block = program.getMemory().join(block, zeroBlock); // expand
						}
						catch (MemoryBlockException | LockException | NotFoundException e) {
							throw new IOException(e);
						}
					}
				}
				else {
					block = MemoryBlockUtils.createUninitializedBlock(program, false, name, addr,
						minalloc, "", "", r, w, x, log);
				}

				if (segments[i].is32bit()) {
					Address end = block.getEnd();

					Register opsizeRegister = context.getRegister("opsize");
					Register addrsizeRegister = context.getRegister("addrsize");

					try {
						context.setValue(opsizeRegister, addr, end, BigInteger.valueOf(1));
						context.setValue(addrsizeRegister, addr, end, BigInteger.valueOf(1));
					}
					catch (ContextChangeException e) {
						// ignore since no instruction should exist at time of import
					}
				}

				StringBuffer buff = new StringBuffer();
				buff.append("Segment:    " + (i + 1) + "\n");
				buff.append(
					"Offset:     " + Conv.toHexString(segments[i].getOffsetShiftAligned()) + "\n");
				buff.append("Length:     " + Conv.toHexString(segments[i].getLength()) + "\n");
				buff.append(
					"Min Alloc:  " + Conv.toHexString(segments[i].getMinAllocSize()) + "\n");
				buff.append("Flags:      " + Conv.toHexString(segments[i].getFlagword()) + "\n");
				buff.append(TAB + (segments[i].isCode() ? "Code" : "Data") + "\n");
				buff.append((segments[i].isDiscardable() ? TAB + "Discardable" + "\n" : ""));
				buff.append((segments[i].isExecuteOnly() ? TAB + "Execute Only" + "\n" : ""));
				buff.append((segments[i].isLoaded() ? TAB + "Loaded" + "\n" : ""));
				buff.append(
					(segments[i].isLoaderAllocated() ? TAB + "LoaderAllocated" + "\n" : ""));
				buff.append(TAB + (segments[i].isMoveable() ? "Moveable" : "Fixed") + "\n");
				buff.append(TAB + (segments[i].isPreload() ? "Preload" : "LoadOnCall") + "\n");
				buff.append(TAB +
					(segments[i].isPure() ? "Pure (Shareable)" : "Impure (Non-shareable)") + "\n");
				buff.append((segments[i].isReadOnly() ? TAB + "Read Only" + "\n" : ""));
				buff.append((segments[i].is32bit() ? TAB + "Use 32 Bit" + "\n" : ""));
				CodeUnit cu = program.getListing().getCodeUnitAt(addr);
				cu.setComment(CodeUnit.PRE_COMMENT, buff.toString());
			}

			for (Segment segment : segments) {
				if (!segment.isCode()) {
					continue;
				}
				Address addr = space.getAddress(segment.getSegmentID(), 0);
				MemoryBlock mb = program.getMemory().getBlock(addr);
				setRegisterDS(ib, st, context, mb.getStart(), mb.getEnd());
			}
		}
		catch (AddressOverflowException e) {
			throw new RuntimeException(e);
		}
	}

	private void processResourceTable(MessageLog log, Program program, ResourceTable rt,
			SegmentedAddressSpace space, FileBytes fileBytes, TaskMonitor monitor) {
		Listing listing = program.getListing();

		if (rt == null) {
			return; //there is not a resource table in this program...
		}

		int id = 0;//this is used to name rsrc mem blocks...
		ResourceType[] types = rt.getResourceTypes();
		for (ResourceType type : types) {
			//String type = types[t].toString();
			Resource[] resources = type.getResources();
			for (Resource resource : resources) {

				int segidx = space.getNextOpenSegment(program.getMemory().getMaxAddress());
				Address addr = space.getAddress(segidx, 0);

				try {
					int offset = resource.getFileOffsetShifted();
					int length = resource.getFileLengthShifted();
					if (length > 0) {
						MemoryBlockUtils.createInitializedBlock(program, false, "Rsrc" + (id++),
							addr, fileBytes, offset, length, "", "", true,
							false, false, log);
					}
				}
				catch (AddressOverflowException e) {
					throw new RuntimeException(e);
				}

				//create a comment to describe this resource...
				StringBuilder buf = new StringBuilder();
				buf.append("Resource Type:  " + Conv.toHexString(type.getTypeID()) + " (" + type +
					")" + "\n");
				buf.append(
					"File Length:    " + Conv.toHexString(resource.getFileLengthShifted()) + "\n");
				buf.append(
					"File Offset:    " + Conv.toHexString(resource.getFileOffsetShifted()) + "\n");
				buf.append("Attributes:     " + Conv.toHexString(resource.getFlagword()) + " (");
				if (resource.isMoveable()) {
					buf.append("Moveable");
				}
				if (resource.isPreload()) {
					buf.append(",Preload");
				}
				if (resource.isPure()) {
					buf.append(",Pure");
				}
				buf.append(")" + "\n");
				buf.append("Resource ID:    " + resource + "\n");
				buf.append("Handle:         " + Conv.toHexString(resource.getHandle()) + "\n");
				buf.append("Usage:          " + Conv.toHexString(resource.getUsage()) + "\n");
				CodeUnit cu = listing.getCodeUnitAt(addr);
				if (cu != null) {
					cu.setComment(CodeUnit.PRE_COMMENT, buf.toString());
				}

				//if this resource is a string table,
				//then go and create the strings...
				if (resource instanceof ResourceStringTable) {
					ResourceStringTable rst = (ResourceStringTable) resource;
					LengthStringSet[] strings = rst.getStrings();
					for (LengthStringSet string : strings) {
						try {
							long dis = string.getIndex() - resource.getFileOffsetShifted();
							Address straddr = addr.addNoWrap(dis);
							listing.createData(straddr, new ByteDataType(), 1);
							straddr = straddr.addNoWrap(1);
							listing.createData(straddr, new StringDataType(),
								Byte.toUnsignedInt(string.getLength()));
						}
						catch (AddressOverflowException | CodeUnitInsertionException e) {
							log.appendMsg("Error creating data");
							log.appendException(e);
						}
					}
				}
			}
		}
	}

	/**
	 * This method creates an artificial memory block
	 * that will serve as a jump table for imported
	 * libraries.
	 */
	private void processModuleReferenceTable(ModuleReferenceTable mrt, SegmentTable st,
			ImportedNameTable imp, Program program, SegmentedAddressSpace space, MessageLog log,
			TaskMonitor monitor) throws IOException {

		int thunkBodySize = 4;

		ExternalManager externalManager = program.getExternalManager();
		FunctionManager functionManager = program.getFunctionManager();
		Namespace globalNamespace = program.getGlobalNamespace();

		LengthStringSet[] names = mrt.getNames();
		String[][] mod2proclist = new String[names.length][];
		int length = 0;
		for (int i = 0; i < names.length; ++i) {
			String moduleName = names[i].getString();
			String[] callnames = getCallNamesForModule(moduleName, mrt, st, imp);
			mod2proclist[i] = callnames;
			length += callnames.length * thunkBodySize;
		}
		if (length == 0) {
			return;
		}
		int segment = space.getNextOpenSegment(program.getMemory().getMaxAddress());
		Address addr = space.getAddress(segment, 0);
		String comment = "";
		String source = "";
		// This isn't a real block, just place holder addresses, so don't create an initialized block
		MemoryBlockUtils.createUninitializedBlock(program, false, MemoryBlock.EXTERNAL_BLOCK_NAME,
			addr, length, comment, source, true, false, false, log);

		for (int i = 0; i < names.length; ++i) {
			String moduleName = names[i].getString();
			String[] callnames = mod2proclist[i];
			for (String callname : callnames) {
				Function refFunction = null;
				try {
					ExternalLocation loc;
					loc = externalManager.addExtFunction(moduleName, callname, null,
						SourceType.IMPORTED);
					refFunction = loc.getFunction();
				}
				catch (DuplicateNameException e) {
					log.appendMsg(e.getMessage() + '\n');
					continue;
				}
				catch (InvalidInputException e) {
					log.appendMsg(e.getMessage() + '\n');
					continue;
				}
				AddressSet body = new AddressSet();
				body.add(addr, addr.add(thunkBodySize - 1));
				try {
					functionManager.createThunkFunction(null, globalNamespace, addr, body,
						refFunction, SourceType.IMPORTED);
				}
				catch (OverlappingFunctionException e) {
					log.appendMsg(e.getMessage() + '\n');
				}
				addr = addr.addWrap(thunkBodySize);
			}
		}
	}

	private String[] getCallNamesForModule(String moduleName, ModuleReferenceTable mrt,
			SegmentTable st, ImportedNameTable imp) throws IOException {

		ArrayList<String> list = new ArrayList<>();
		Segment[] segments = st.getSegments();
		for (Segment segment : segments) {
			SegmentRelocation[] relocs = segment.getRelocations();
			for (SegmentRelocation reloc : relocs) {
				if (moduleName.equals(getRelocationModuleName(mrt, reloc))) {
					String procname = getRelocationProcName(reloc, imp);
					if (!list.contains(procname)) {
						list.add(procname);
					}
				}
			}
		}
		String[] callnames = new String[list.size()];
		list.toArray(callnames);
		Arrays.sort(callnames, comparator);
		return callnames;
	}

	private class CallNameComparator implements Comparator<String> {
		private int prefixLength = SymbolUtilities.ORDINAL_PREFIX.length();

		@Override
		public int compare(String s1, String s2) {
			if (s1.startsWith(SymbolUtilities.ORDINAL_PREFIX) &&
				s2.startsWith(SymbolUtilities.ORDINAL_PREFIX)) {
				int i1 = Integer.parseInt(s1.substring(prefixLength));
				int i2 = Integer.parseInt(s2.substring(prefixLength));
				if (i1 < i2) {
					return -1;
				}
				if (i1 > i2) {
					return 1;
				}
				return 0;
			}
			return s1.compareTo(s2);
		}
	}

	private void processEntryTable(SegmentTable st, InformationBlock ib, EntryTable et,
			SymbolTable symbolTable, SegmentedAddressSpace space, MessageLog log) {

		//process the main entry point defined in the information block...
		short segmentIdx = ib.getEntryPointSegment();
		if (segmentIdx > 0) {
			int segment = st.getSegments()[segmentIdx - 1].getSegmentID();
			short offset = ib.getEntryPointOffset();
			Address entryAddr = space.getAddress(segment, Short.toUnsignedInt(offset));
			symbolTable.addExternalEntryPoint(entryAddr);
			try {
				symbolTable.createLabel(entryAddr, "entry", SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				log.appendMsg("Error creating label at " + entryAddr);
				log.appendException(e);
			}
		}

		//process the entry table bundles...
		EntryTableBundle[] bundles = et.getBundles();
		for (EntryTableBundle bundle : bundles) {
			if (bundle.getType() == EntryTableBundle.UNUSED) {
				int count = Byte.toUnsignedInt(bundle.getCount());
				for (int i = 0; i < count; ++i) {
					entryPointList.add(null);
				}
				continue;
			}
			EntryPoint[] pts = bundle.getEntryPoints();
			for (EntryPoint pt : pts) {
				int seg = 0;
				if (bundle.isMoveable()) {
					int segmentIndex = Byte.toUnsignedInt(pt.getSegment()) - 1;
					if (segmentIndex < 0 || segmentIndex >= st.getSegments().length) {
						log.appendMsg("Invalid segmentIndex " + segmentIndex);
						continue;
					}
					seg = st.getSegments()[segmentIndex].getSegmentID();
				}
				else if (bundle.isConstant()) {
					//todo: how to handle constants...?
					log.appendMsg("NE - constant entry point...");
				}
				else {
					seg = st.getSegments()[bundle.getType() - 1].getSegmentID();
				}
				int off = Short.toUnsignedInt(pt.getOffset());
				Address addr = space.getAddress(seg, off);
				symbolTable.addExternalEntryPoint(addr);

				entryPointList.add(addr); //hang onto address at ordinal value...
			}
		}
	}

	private void processNonResidentNameTable(NonResidentNameTable nrnt, SymbolTable symbolTable) {
		createSymbols(nrnt.getNames(), symbolTable);
	}

	private void processResidentNameTable(ResidentNameTable rnt, SymbolTable symbolTable) {
		createSymbols(rnt.getNames(), symbolTable);
	}

	private SegmentedAddress getImportSymbolByName(SymbolTable symbolTable, String modname,
			String procname) {
		Namespace libnamespace = symbolTable.getNamespace(modname, null);
		List<Symbol> symbols = symbolTable.getSymbols(procname, libnamespace);
		if (symbols.isEmpty()) {
			return null;
		}
		Symbol symbol = symbols.get(0);
		if (symbol.getSymbolType() == SymbolType.FUNCTION && symbol.isExternal()) {
			Function func = (Function) symbol.getObject();
			Address[] thunkAddresses = func.getFunctionThunkAddresses(false);
			if (thunkAddresses != null && thunkAddresses.length != 0) {
				return (SegmentedAddress) thunkAddresses[0];
			}
		}
		return null;
	}

	private void processRelocations(SegmentTable st, ImportedNameTable imp,
			ModuleReferenceTable mrt, RelocationTable relocTable, Program program, Memory memory,
			SegmentedAddressSpace space, MessageLog log, TaskMonitor monitor) throws IOException {
		SymbolTable symbolTable = program.getSymbolTable();
		Segment[] segments = st.getSegments();
		for (int s = 0; s < segments.length; ++s) {
			if (monitor.isCancelled()) {
				return;
			}
			SegmentRelocation[] relocs = segments[s].getRelocations();
			for (SegmentRelocation reloc : relocs) {
				if (monitor.isCancelled()) {
					return;
				}

				int segment = st.getSegments()[s].getSegmentID();
				int offset = Short.toUnsignedInt(reloc.getOffset());
				SegmentedAddress relocAddr = null;

				if (reloc.isInternalRef()) {
					if (reloc.getTargetSegment() == SegmentRelocation.MOVEABLE) {
						relocAddr = (SegmentedAddress) entryPointList.get(reloc.getTargetOffset());
					}
					else {
						int seg = st.getSegments()[reloc.getTargetSegment() - 1].getSegmentID();
						int off = Short.toUnsignedInt(reloc.getTargetOffset());
						relocAddr = space.getAddress(seg, off);
					}
				}
				else if (reloc.isImportName()) {
					String modname = getRelocationModuleName(mrt, reloc);
					String procname = imp.getNameAt(reloc.getTargetOffset()).getString();
					relocAddr = getImportSymbolByName(symbolTable, modname, procname);
				}
				else if (reloc.isImportOrdinal()) {
					String modname = getRelocationModuleName(mrt, reloc);
					int ordinal = Short.toUnsignedInt(reloc.getTargetOffset());
					String procname = SymbolUtilities.ORDINAL_PREFIX + ordinal;
					relocAddr = getImportSymbolByName(symbolTable, modname, procname);
				}
				else if (reloc.isOpSysFixup()) {
					// short fixupType = relocs[r].getTargetSegment();
					//todo: import os fixup...
				}

				if (relocAddr == null) {
					continue;
				}

				int relocType = reloc.getType();

				do {
					SegmentedAddress address = space.getAddress(segment, offset);
					try {
						byte[] bytes = new byte[SegmentRelocation.TYPE_LENGTHS[relocType]];
						memory.getBytes(address, bytes);

						relocTable.add(address, relocType, reloc.getValues(), bytes, null);
						offset = relocate(memory, reloc, address, relocAddr);
					}
					catch (MemoryAccessException e) {
						log.appendMsg("Relocation does not exist in memory: " + relocAddr);
						break;
					}
					if (reloc.isAdditive()) {
						break;
					}
					if (offset <= 0 || offset >= 0xffff) {
						break;
					}
					if (monitor.isCancelled()) {
						break;
					}
				}
				while (true);
			}
		}
	}

	private int relocate(Memory memory, SegmentRelocation reloc, SegmentedAddress address,
			SegmentedAddress relocAddr) throws MemoryAccessException {

		int value = 0;
		switch (reloc.getType()) {
			case SegmentRelocation.TYPE_LO_BYTE: {
				value = memory.getByte(address) & 0xff;

				memory.setByte(address, (byte) relocAddr.getSegmentOffset());
				break;
			}
			case SegmentRelocation.TYPE_SEGMENT: {
				value = memory.getShort(address) & 0xffff;

				int relocSeg = relocAddr.getSegment();
				memory.setByte(address, (byte) (relocSeg));
				memory.setByte(address.addWrap(1), (byte) (relocSeg >> 8));
				break;
			}
			case SegmentRelocation.TYPE_OFFSET: {
				value = memory.getShort(address) & 0xffff;

				long relocOff = relocAddr.getSegmentOffset();
				memory.setByte(address, (byte) (relocOff));
				memory.setByte(address.addWrap(1), (byte) (relocOff >> 8));
				break;
			}
			case SegmentRelocation.TYPE_FAR_ADDR: {
				value = memory.getInt(address);

				int relocSeg = relocAddr.getSegment();
				long relocOff = relocAddr.getSegmentOffset();

				long farAddr = relocSeg << 16 | relocOff;

				if (reloc.isAdditive()) {
					farAddr += value;
				}
				memory.setInt(address, (int) farAddr);
				break;
			}
			case SegmentRelocation.TYPE_FAR_ADDR_48: {
				break;
			}
			case SegmentRelocation.TYPE_OFFSET_32: {
				break;
			}
		}
		return value;
	}

	private String getRelocationModuleName(ModuleReferenceTable mrt, SegmentRelocation reloc) {
		if (reloc.isImportName() || reloc.isImportOrdinal()) {
			LengthStringSet[] names = mrt.getNames();
			return names[reloc.getTargetSegment() - 1].getString();
		}
		return null;
	}

	private String getRelocationProcName(SegmentRelocation reloc, ImportedNameTable imp)
			throws IOException {
		if (reloc.isImportName()) {
			return imp.getNameAt(reloc.getTargetOffset()).getString();
		}
		else if (reloc.isImportOrdinal()) {
			int ordinal = Short.toUnsignedInt(reloc.getTargetOffset());
			return SymbolUtilities.ORDINAL_PREFIX + ordinal;
		}
		return null;
	}

	private void initVars() {
		entryPointList.clear();
		entryPointList.add(null); //add a null, since ordinals start at 1, not 0...
	}

	/**
	 *  In order to disassemble correctly, we need to set the 'ds' register.
	 */
	private void setRegisterDS(InformationBlock ib, SegmentTable segmentTable,
			ProgramContext context, Address start, Address end) {

		byte progflag = ib.getProgramFlags();

		boolean isSingleData = (progflag & InformationBlock.FLAGS_PROG_SINGLE_DATA) != 0;
		boolean isMultipleData = (progflag & InformationBlock.FLAGS_PROG_MULTIPLE_DATA) != 0;

		Register ds = context.getRegister("DS");

		try {
			if (isSingleData || isMultipleData) {
				short autoDataSeg = ib.getAutomaticDataSegment();
				long regval = segmentTable.getSegments()[autoDataSeg - 1].getSegmentID();
				context.setValue(ds, start, end, BigInteger.valueOf(regval));
			}
			else {
				context.remove(start, end, ds);
			}
		}
		catch (ContextChangeException e) {
			// ignore since DS register should never cause this error
		}
	}

	private void createSymbols(LengthStringOrdinalSet[] lengthStringOrdinalSets,
			SymbolTable symbolTable) {
		for (LengthStringOrdinalSet lengthStringOrdinalSet : lengthStringOrdinalSets) {
			int ordinal = Short.toUnsignedInt(lengthStringOrdinalSet.getOrdinal());
			if (ordinal >= entryPointList.size()) {
				continue;
			}
			Address addr = entryPointList.get(ordinal);
			if (addr == null) {
				continue;
			}
			String name = lengthStringOrdinalSet.getString();
			name = SymbolUtilities.replaceInvalidChars(name, true);
			try {
				symbolTable.createLabel(addr, name, SourceType.IMPORTED);
				symbolTable.createLabel(addr, SymbolUtilities.ORDINAL_PREFIX + ordinal,
					SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				Msg.error(this, "Error creating label " + name + "@" + addr, e);
			}
		}
	}

	@Override
	public String getName() {
		return NE_NAME;
	}

}

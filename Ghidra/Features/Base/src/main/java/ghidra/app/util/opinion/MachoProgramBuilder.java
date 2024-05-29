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

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import org.apache.commons.collections4.map.LazySortedMap;

import ghidra.app.plugin.core.analysis.rust.RustConstants;
import ghidra.app.plugin.core.analysis.rust.RustUtilities;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.RelocationException;
import ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress;
import ghidra.app.util.bin.format.golang.GoBuildId;
import ghidra.app.util.bin.format.golang.GoBuildInfo;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.app.util.bin.format.macho.commands.ExportTrie.ExportEntry;
import ghidra.app.util.bin.format.macho.commands.chained.*;
import ghidra.app.util.bin.format.macho.commands.dyld.*;
import ghidra.app.util.bin.format.macho.commands.dyld.BindingTable.Binding;
import ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.DyldChainType;
import ghidra.app.util.bin.format.macho.dyld.DyldFixup;
import ghidra.app.util.bin.format.macho.relocation.*;
import ghidra.app.util.bin.format.macho.threadcommand.ThreadCommand;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Constants;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.ExternalSymbolResolver;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Builds up a Mach-O {@link Program} by parsing the Mach-O headers.
 */
public class MachoProgramBuilder {

	public static final String BLOCK_SOURCE_NAME = "Mach-O Loader";

	protected MachHeader machoHeader;

	protected Program program;
	protected ByteProvider provider;
	protected FileBytes fileBytes;
	protected MessageLog log;
	protected TaskMonitor monitor;
	protected Memory memory;
	protected Listing listing;
	protected AddressSpace space;
	protected BinaryReader reader;

	private Map<String, AddressSpace> segmentOverlayMap;

	/**
	 * Creates a new {@link MachoProgramBuilder} based on the given information.
	 * 
	 * @param program The {@link Program} to build up.
	 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
	 * @param fileBytes Where the Mach-O's bytes came from.
	 * @param log The log.
	 * @param monitor A cancelable task monitor.
	 */
	protected MachoProgramBuilder(Program program, ByteProvider provider, FileBytes fileBytes,
			MessageLog log, TaskMonitor monitor) {
		this.program = program;
		this.provider = provider;
		this.fileBytes = fileBytes;
		this.log = log;
		this.monitor = monitor;
		this.memory = program.getMemory();
		this.listing = program.getListing();
		this.space = program.getAddressFactory().getDefaultAddressSpace();
		this.reader = new BinaryReader(provider, !memory.isBigEndian());
		this.segmentOverlayMap = new HashMap<>();
	}

	/**
	 * Builds up a Mach-O {@link Program}.
	 * 
	 * @param program The {@link Program} to build up.
	 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
	 * @param fileBytes Where the Mach-O's bytes came from.
	 * @param log The log.
	 * @param monitor A cancelable task monitor.
	 * @throws Exception if a problem occurs.
	 */
	public static void buildProgram(Program program, ByteProvider provider, FileBytes fileBytes,
			MessageLog log, TaskMonitor monitor) throws Exception {
		MachoProgramBuilder machoProgramBuilder =
			new MachoProgramBuilder(program, provider, fileBytes, log, monitor);
		machoProgramBuilder.build();
	}

	protected void build() throws Exception {

		monitor.setMessage("Completing Mach-O header parsing...");
		monitor.setCancelEnabled(false);
		machoHeader = new MachHeader(provider);
		machoHeader.parse();
		monitor.setCancelEnabled(true);

		// Setup memory
		setProgramImageBase();
		processMemoryBlocks(machoHeader, provider.getName(), true, true);

		// Process load commands
		processEntryPoint();
		boolean exportsFound = processExports(machoHeader);
		processSymbolTables(machoHeader, !exportsFound);
		processStubs();
		processUndefinedSymbols();
		processAbsoluteSymbols();
		List<String> libraryPaths = processLibraries();
		List<Address> chainedFixups = processChainedFixups(libraryPaths);
		processDyldInfo(false, libraryPaths);
		processSectionRelocations();
		processExternalRelocations();
		processLocalRelocations();
		processEncryption();
		processUnsupportedLoadCommands();
		processCorruptLoadCommands();

		// Markup structures
		markupHeaders(machoHeader, setupHeaderAddr(machoHeader.getAllSegments()));
		markupSections();
		markupLoadCommandData(machoHeader, provider.getName());
		markupChainedFixups(machoHeader, chainedFixups);
		markupProgramVars();

		// Set program info
		setRelocatableProperty();
		setProgramDescription();
		if (GoRttiMapper.isGolangProgram(program)) {
			markupAndSetGolangInitialProgramProperties();
		}

		// Perform additional actions
		renameObjMsgSendRtpSymbol();
		fixupProgramTree(null); // should be done last to account for new memory blocks
		setCompiler();
	}

	/**
	 * Sets the {@link Program} image base
	 * 
	 * @throws Exception if there was a problem setting the {@link Program} image base
	 */
	protected void setProgramImageBase() throws Exception {
		program.setImageBase(getMachoBaseAddress(), true);
	}

	/**
	 * Gets the base address of this Mach-O. This is the address of the start of the Mach-O, not
	 * necessary the {@link Program} image base.
	 * 
	 * @return The base address of this Mach-O
	 */
	protected Address getMachoBaseAddress() {
		Address lowestAddr = null;
		for (SegmentCommand segment : machoHeader.getAllSegments()) {
			if (segment.getFileSize() > 0) {
				Address segmentAddr = space.getAddress(segment.getVMaddress());
				if (lowestAddr == null) {
					lowestAddr = segmentAddr;
				}
				else if (segmentAddr.compareTo(lowestAddr) < 0) {
					lowestAddr = segmentAddr;
				}
			}
		}
		return lowestAddr != null ? lowestAddr : space.getAddress(0);
	}

	/**
	 * Creates memory blocks for the given header.  
	 * 
	 * @param header The Mach-O header to process for memory block creation.
	 * @param source A name that represents where the memory blocks came from.
	 * @param processSections True to split segments into their sections.
	 * @param allowZeroAddr True if memory blocks at address 0 should be processed; otherwise, 
	 *   false.
	 * @throws Exception If there was a problem processing the memory blocks.
	 */
	protected void processMemoryBlocks(MachHeader header, String source, boolean processSections,
			boolean allowZeroAddr) throws Exception {
		monitor.setMessage("Processing memory blocks for " + source + "...");

		if (header.getFileType() == MachHeaderFileTypes.MH_DYLIB_STUB) {
			return;
		}

		Set<Section> overlaySections = new HashSet<>();

		// Create memory blocks for segments.
		for (SegmentCommand segment : header.getAllSegments()) {
			if (monitor.isCancelled()) {
				break;
			}

			if (segment.getFileSize() > 0 && segment.getVMsize() > 0 &&
				(allowZeroAddr || segment.getVMaddress() != 0)) {
				if (createMemoryBlock(segment.getSegmentName(),
					space.getAddress(segment.getVMaddress()), segment.getFileOffset(),
					segment.getFileSize(), segment.getSegmentName(), source, segment.isRead(),
					segment.isWrite(), segment.isExecute(), false, false) == null) {
					log.appendMsg(String.format("Failed to create block: %s 0x%x 0x%x",
						segment.getSegmentName(), segment.getVMaddress(), segment.getVMsize()));
				}
				if (segment.getVMsize() > segment.getFileSize()) {
					// Pad the remaining address range with uninitialized data
					if (createMemoryBlock(segment.getSegmentName(),
						space.getAddress(segment.getVMaddress()).add(segment.getFileSize()), 0,
						segment.getVMsize() - segment.getFileSize(), segment.getSegmentName(),
						source, segment.isRead(), segment.isWrite(), segment.isExecute(),
						true, false) == null) {
						log.appendMsg(String.format("Failed to create block: %s 0x%x 0x%x",
							segment.getSegmentName(), segment.getVMaddress(), segment.getVMsize()));
					}
				}
			}
			else if (segment.getVMaddress() != 0 && segment.getVMsize() == 0 &&
				segment.getFileSize() > 0) {
				MemoryBlock overlayBlock = createMemoryBlock(segment.getSegmentName(),
					space.getAddress(segment.getVMaddress()), segment.getFileOffset(),
					segment.getFileSize(), segment.getSegmentName(), source, true, false, false,
					false, true);
				if (overlayBlock == null) {
					log.appendMsg(String.format("Failed to create overlay block: %s 0x%x 0x%x",
						segment.getSegmentName(), segment.getVMaddress(), segment.getVMsize()));
				}
				else {
					segmentOverlayMap.put(segment.getSegmentName(), overlayBlock.getStart().getAddressSpace());
					overlaySections.addAll(segment.getSections());
				}
			}
		}

		// Create memory blocks for sections.  They will be in the segments we just created, so the
		// segment blocks will be split and possibly replaced.
		if (processSections) {
			for (Section section : header.getAllSections()) {
				if (monitor.isCancelled()) {
					break;
				}
				AddressSpace sectionSpace = overlaySections.contains(section)
						? segmentOverlayMap.get(section.getSegmentName())
						: space;
				if (section.getSize() > 0 && section.getOffset() > 0 &&
					(allowZeroAddr || section.getAddress() != 0)) {
					if (createMemoryBlock(section.getSectionName(),
						sectionSpace.getAddress(section.getAddress()), section.getOffset(),
						section.getSize(), section.getSegmentName(), source, section.isRead(),
						section.isWrite(), section.isExecute(),
						section.getType() == SectionTypes.S_ZEROFILL, false) == null) {
						log.appendMsg(String.format("Failed to create block: %s.%s 0x%x 0x%x %s",
							section.getSegmentName(), section.getSectionName(),
							section.getAddress(), section.getSize(), source));
					}
				}
			}
		}
	}

	/**
	 * Creates a memory with the provided attributes.  The block we wish to create may reside inside
	 * an already-created block. If this is the case, we split the outer block(s) that encompass our
	 * desired new block. This is the nature of Mach-O segments and sections (sections are
	 * contained in segments).
	 * 
	 * @param name The name of the new block.
	 * @param start The starting address of the new block.
	 * @param dataOffset The provider offset of the new block.
	 * @param dataLength The length of the new block.
	 * @param comment A comment for the new block.
	 * @param source The source name of the new block.
	 * @param r True if the new block has read-permissions; otherwise, false.
	 * @param w True if the new block has write-permissions; otherwise, false.
	 * @param x True if the new block has execute-permissions; otherwise, false.
	 * @param zeroFill True if the new block is zero-filled; otherwise, false.  Newly created
	 *   zero-filled blocks will be uninitialized to safe space.
	 * @param overlay True if the new block should be an overlay; otherwise, false.
	 * @return The newly created (or split) memory block, or null if it failed to be created. 
	 * @throws Exception If there was a problem creating the new memory block.
	 */
	private MemoryBlock createMemoryBlock(String name, Address start, long dataOffset,
			long dataLength, String comment, String source, boolean r, boolean w, boolean x,
			boolean zeroFill, boolean overlay) throws Exception {

		// Get a list of all blocks that intersect with the block we wish to create.  There may be
		// more that one if the containing memory has both initialized and uninitialized pieces.
		List<MemoryBlock> intersectingBlocks = new ArrayList<>();
		AddressSet range = new AddressSet(start, start.add(dataLength - 1));
		for (MemoryBlock block : memory.getBlocks()) {
			if (range.intersects(block.getStart(), block.getEnd())) {
				intersectingBlocks.add(block);
			}
		}

		// If we have no intersecting blocks, create a new block.  We are assuming that if we do
		// intersect with at least one block, we will be completely contained in that block(s).
		// If that assumption is wrong, the Mach-O headers may be malformed (or we don't fully
		// understand them).
		if (intersectingBlocks.isEmpty()) {
			if (zeroFill) {
				// Treat zero-fill blocks as uninitialized to save space
				return MemoryBlockUtils.createUninitializedBlock(program, overlay, name, start,
					dataLength, comment, source, r, w, x, log);
			}

			return MemoryBlockUtils.createInitializedBlock(program, overlay, name, start, fileBytes,
				dataOffset, dataLength, comment, source, r, w, x, log);
		}

		// Split the starting block (if necessary).  Splitting is not necessary if the start of our 
		// new block begins exactly where the starting block begins.
		MemoryBlock startingBlock = intersectingBlocks.get(0);
		if (start.compareTo(startingBlock.getStart()) > 0) {
			memory.split(startingBlock, start);

		}

		// Split the ending block (if necessary).  Splitting is not necessary if the end of our new
		// block ends exactly where the ending block ends.  We need to fix up the name of the split 
		// block so it doesn't end in ".split"
		MemoryBlock endingBlock = intersectingBlocks.get(intersectingBlocks.size() - 1);
		if (start.add(dataLength - 1).compareTo(endingBlock.getEnd()) < 0) {
			memory.split(endingBlock, start.add(dataLength));
			MemoryBlock newEndingBlock = memory.getBlock(start.add(dataLength));
			newEndingBlock.setName(endingBlock.getName());
			newEndingBlock.setSourceName(endingBlock.getSourceName());
			newEndingBlock.setComment(endingBlock.getComment());
		}

		// Change the attributes of all the blocks that intersect with the block we wish to create
		for (MemoryBlock block : memory.getBlocks()) {
			if (range.intersects(block.getStart(), block.getEnd())) {
				block.setName(name);
				block.setPermissions(r, w, x);
				block.setSourceName(source);
				block.setComment(comment);
			}
		}

		return memory.getBlock(start);
	}

	/**
	 * Fixes up the Program Tree to better visualize the memory blocks that were split into sections
	 * 
	 * @param suffix An optional suffix that will get appended to tree segment and segment nodes
	 * @throws Exception if there was a problem fixing up the Program Tree
	 */
	protected void fixupProgramTree(String suffix) throws Exception {
		if (suffix == null) {
			suffix = "";
		}
		ProgramModule rootModule = listing.getDefaultRootModule();
		for (SegmentCommand segment : machoHeader.getAllSegments()) {
			AddressSpace segmentSpace =
				segmentOverlayMap.getOrDefault(segment.getSegmentName(), space);
			Address segmentStart = segmentSpace.getAddress(segment.getVMaddress());
			Address segmentEnd = segmentStart.add(segment.getVMsize() - 1);
			if (!memory.contains(segmentStart)) {
				continue;
			}
			if (!memory.contains(segmentEnd)) {
				segmentEnd = memory.getBlock(segmentStart).getEnd();
			}
			// Move original segment fragment into module and rename it.  After we add new 
			// section fragments, it will represent the parts of the segment that weren't in any
			// section.
			String segmentName = segment.getSegmentName();
			String noSectionsName = segmentName + " <no section>" + suffix;
			ProgramFragment segmentFragment = null;
			for (Group group : rootModule.getChildren()) {
				if (group instanceof ProgramFragment fragment &&
					fragment.getName().equals(segmentName)) {
					fragment.setName(noSectionsName);
					segmentFragment = fragment;
					break;
				}
			}
			if (segmentFragment == null) {
				log.appendMsg("Could not find/fixup segment in Program Tree: " + segmentName);
				continue;
			}
			ProgramModule segmentModule = rootModule.createModule(segmentName + suffix);
			try {
				segmentModule.reparent(noSectionsName, rootModule);
			}
			catch (NotFoundException e) {
				log.appendException(e);
				continue;
			}

			// Add the sections, which will remove overlapped ranges from the segment fragment
			for (Section section : segment.getSections()) {
				if (section.getSize() == 0) {
					continue;
				}
				Address sectionStart = segmentSpace.getAddress(section.getAddress());
				Address sectionEnd = sectionStart.add(section.getSize() - 1);
				if (!memory.contains(sectionEnd)) {
					sectionEnd = memory.getBlock(sectionStart).getEnd();
				}
				ProgramFragment sectionFragment =
					segmentModule.createFragment(String.format("%s %s", section.getSegmentName(),
						section.getSectionName() + suffix));
				sectionFragment.move(sectionStart, sectionEnd);
			}

			// If the sections fully filled the segment, we can remove the now-empty segment
			if (segmentFragment.isEmpty()) {
				segmentModule.removeChild(segmentFragment.getName());
			}
		}

		// Update EXTERNAL block if it exists
		for (Group group : rootModule.getChildren()) {
			if (group instanceof ProgramFragment fragment &&
				fragment.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME)) {
				fragment.setName(MemoryBlock.EXTERNAL_BLOCK_NAME + suffix);
				break;
			}
		}
	}

	/**
	 * Attempts to discover and set the entry point.
	 * <p>
	 * A program may declare multiple entry points to, for example, confuse static analysis tools.
	 * We will sort the discovered entry points by priorities assigned to each type of load
	 * command, and only use the one with the highest priority.
	 * 
	 * @throws Exception If there was a problem discovering or setting the entry point.
	 */
	protected void processEntryPoint() throws Exception {
		monitor.setMessage("Processing entry point...");

		final int LC_MAIN_PRIORITY = 1;
		final int LC_UNIX_THREAD_PRIORITY = 2;
		final int LC_THREAD_PRIORITY = 3;
		SortedMap<Integer, List<Address>> priorityMap =
			LazySortedMap.lazySortedMap(new TreeMap<>(), () -> new ArrayList<>());

		for (EntryPointCommand cmd : machoHeader.getLoadCommands(EntryPointCommand.class)) {
			long offset = cmd.getEntryOffset();
			if (offset > 0) {
				SegmentCommand segment = machoHeader.getSegment("__TEXT");
				if (segment != null) {
					priorityMap.get(LC_MAIN_PRIORITY)
							.add(space.getAddress(segment.getVMaddress()).add(offset));
				}
			}
		}

		for (ThreadCommand threadCommand : machoHeader.getLoadCommands(ThreadCommand.class)) {
			int priority = threadCommand.getCommandType() == LoadCommandTypes.LC_UNIXTHREAD
					? LC_UNIX_THREAD_PRIORITY
					: LC_THREAD_PRIORITY;
			long pointer = threadCommand.getInitialInstructionPointer();
			if (pointer != -1) {
				priorityMap.get(priority).add(space.getAddress(pointer));
			}
		}

		if (!priorityMap.isEmpty()) {
			boolean realEntryFound = false;
			for (List<Address> addrs : priorityMap.values()) {
				for (Address addr : addrs) {
					if (!realEntryFound) {
						program.getSymbolTable().createLabel(addr, "entry", SourceType.IMPORTED);
						program.getSymbolTable().addExternalEntryPoint(addr);
						createOneByteFunction("entry", addr);
						realEntryFound = true;
					}
					else {
						log.appendMsg("Ignoring entry point at: " + addr);
					}
				}
			}
		}
		else {
			log.appendMsg("Unable to determine entry point.");
		}
	}

	protected boolean processExports(MachHeader header) throws Exception {
		monitor.setMessage("Processing exports...");

		List<ExportEntry> exports = new ArrayList<>();

		// Old way - export tree in DyldInfoCommand
		List<DyldInfoCommand> dyldInfoCommands = header.getLoadCommands(DyldInfoCommand.class);
		for (DyldInfoCommand dyldInfoCommand : dyldInfoCommands) {
			exports.addAll(dyldInfoCommand.getExportTrie().getExports(e -> !e.isReExport()));

		}

		// New way - export tree in DyldExportsTrieCommand
		List<DyldExportsTrieCommand> dyldExportsTrieCommands =
			header.getLoadCommands(DyldExportsTrieCommand.class);
		for (DyldExportsTrieCommand dyldExportsTreeCommand : dyldExportsTrieCommands) {
			exports.addAll(dyldExportsTreeCommand.getExportTrie().getExports(e -> !e.isReExport()));
		}

		if (exports.isEmpty()) {
			return false;
		}

		SegmentCommand textSegment = header.getSegment(SegmentNames.SEG_TEXT);
		if (textSegment == null) {
			log.appendMsg("Cannot process exports, __TEXT segment not found!");
			return false;
		}

		Address baseAddr = space.getAddress(textSegment.getVMaddress());
		for (ExportEntry export : exports) {
			String name = SymbolUtilities.replaceInvalidChars(export.name(), true);
			try {
				processNewExport(baseAddr, export, name);
			}
			catch (AddressOutOfBoundsException e) {
				log.appendMsg("Failed to process export '" + export + "': " + e.getMessage());
			}
			catch (Exception e) {
				log.appendMsg("Unable to create symbol: " + e.getMessage());
			}
		}

		return !exports.isEmpty();
	}

	protected void processNewExport(Address baseAddr, ExportEntry export, String name)
			throws AddressOutOfBoundsException, Exception {
		Address exportAddr = baseAddr.add(export.address());
		program.getSymbolTable().addExternalEntryPoint(exportAddr);
		program.getSymbolTable().createLabel(exportAddr, name, SourceType.IMPORTED);
	}

	protected void processSymbolTables(MachHeader header, boolean processExports) throws Exception {
		monitor.setMessage("Processing symbol tables...");
		SymbolTable symbolTable = program.getSymbolTable();
		List<SymbolTableCommand> commands = header.getLoadCommands(SymbolTableCommand.class);
		for (SymbolTableCommand symbolTableCommand : commands) {
			List<NList> symbols = symbolTableCommand.getSymbols();
			for (NList symbol : symbols) {
				if (monitor.isCancelled()) {
					return;
				}

				if (symbol.isTypePreboundUndefined()) {
					continue;
				}
				if (symbol.isLazyBind()) {
					continue;
				}

				Address addr = space.getAddress(symbol.getValue());

				if (symbol.isSymbolicDebugging()) {
					continue;
				}
				if (symbol.isTypeAbsolute()) {
					continue;
				}
				if (symbol.isTypeUndefined()) {
					continue;
				}

				// is a re-exported symbol, will be added as an external later
				if (symbol.isIndirect()) {
					continue;
				}

				if (processExports && symbol.isExternal()) {
					symbolTable.addExternalEntryPoint(addr);
				}

				String string = symbol.getString();
				if (string.length() == 0) {
					continue;
				}
				string = SymbolUtilities.replaceInvalidChars(string, true);

				if (symbol.isThumbSymbol()) {
					markAsThumb(addr);
				}

				if (symbolTable.getGlobalSymbol(string, addr) != null) {
					continue;
				}
				try {
					if (!symbol.isExternal() || processExports) {
						Symbol primary = symbolTable.getPrimarySymbol(addr);
						Symbol newSymbol =
							symbolTable.createLabel(addr, string, SourceType.IMPORTED);
						if (primary != null && primary.getName().equals("<redacted>")) {
							newSymbol.setPrimary();
						}
						if (symbol.isExternal()) {
							symbolTable.addExternalEntryPoint(addr);
						}
					}
				}
				catch (Exception e) {
					log.appendMsg("Unable to create symbol: " + e.getMessage());
				}
			}
		}
	}

	protected void processStubs() throws Exception {
		monitor.setMessage("Processing stubs...");

		SymbolTableCommand symbolTableCommand =
			machoHeader.getFirstLoadCommand(SymbolTableCommand.class);

		DynamicSymbolTableCommand dynamicCommand =
			machoHeader.getFirstLoadCommand(DynamicSymbolTableCommand.class);

		if (dynamicCommand == null) {
			return;
		}
		int[] indirectSymbols = dynamicCommand.getIndirectSymbols();
		if (indirectSymbols.length == 0) {
			return;
		}

		for (Section section : machoHeader.getAllSections()) {
			if (monitor.isCancelled()) {
				return;
			}
			if (section.getSize() == 0 || section.getType() != SectionTypes.S_SYMBOL_STUBS) {
				continue;
			}

			int indirectSymbolTableIndex = section.getReserved1();

			int symbolSize = machoHeader.getAddressSize();
			if (section.getType() == SectionTypes.S_SYMBOL_STUBS) {
				symbolSize = section.getReserved2();
			}

			int nSymbols = (int) section.getSize() / symbolSize;

			Address startAddr = space.getAddress(section.getAddress());
			for (int i = indirectSymbolTableIndex; i < indirectSymbolTableIndex + nSymbols; ++i) {
				if (monitor.isCancelled()) {
					break;
				}
				int symbolIndex = indirectSymbols[i];
				NList symbol = symbolTableCommand.getSymbolAt(symbolIndex);
				if (symbol == null) {
					continue;
				}
				String name = SymbolUtilities.replaceInvalidChars(symbol.getString(), true);
				if (name != null && name.length() > 0) {
					Function stubFunc = createOneByteFunction(name, startAddr);
					if (stubFunc != null) {
						ExternalLocation loc = program.getExternalManager()
								.addExtLocation(Library.UNKNOWN, name, null, SourceType.IMPORTED);
						stubFunc.setThunkedFunction(loc.createFunction());
					}
				}

				startAddr = startAddr.add(symbolSize);
			}
		}
	}

	protected void processUndefinedSymbols() throws Exception {

		monitor.setMessage("Processing undefined symbols...");
		List<NList> undefinedSymbols = new ArrayList<>();
		List<LoadCommand> commands = machoHeader.getLoadCommands();
		for (LoadCommand command : commands) {
			if (monitor.isCancelled()) {
				return;
			}
			if (!(command instanceof SymbolTableCommand)) {
				continue;
			}
			SymbolTableCommand symbolTableCommand = (SymbolTableCommand) command;
			List<NList> symbols = symbolTableCommand.getSymbols();
			for (NList symbol : symbols) {
				if (monitor.isCancelled()) {
					return;
				}
				if (symbol.isSymbolicDebugging()) {
					continue;
				}
				if (symbol.isTypeUndefined()) {
					List<Symbol> globalSymbols = program.getSymbolTable()
							.getLabelOrFunctionSymbols(symbol.getString(), null);
					if (globalSymbols.isEmpty()) {//IF IT DOES NOT ALREADY EXIST...
						undefinedSymbols.add(symbol);
					}
				}
			}
		}
		if (undefinedSymbols.size() == 0) {
			return;
		}
		Address start = getAddress();
		try {
			MemoryBlock block = memory.createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME,
				start, undefinedSymbols.size() * machoHeader.getAddressSize(), false);
			// assume any value in external is writable.
			block.setWrite(true);

			// Mark block as an artificial fabrication
			block.setArtificial(true);

			block.setSourceName(BLOCK_SOURCE_NAME);
			block.setComment(
				"NOTE: This block is artificial and is used to make relocations work correctly");
		}
		catch (Exception e) {
			log.appendMsg("Unable to create undefined memory block: " + e.getMessage());
		}
		for (NList symbol : undefinedSymbols) {
			if (monitor.isCancelled()) {
				return;
			}
			try {
				String name = SymbolUtilities.replaceInvalidChars(symbol.getString(), true);
				if (name != null && name.length() > 0) {
					program.getSymbolTable().createLabel(start, name, SourceType.IMPORTED);
					program.getExternalManager()
							.addExtLocation(Library.UNKNOWN, name, start, SourceType.IMPORTED);
				}
			}
			catch (Exception e) {
				log.appendMsg("Unable to create undefined symbol: " + e.getMessage());
			}
			start = start.add(machoHeader.getAddressSize());
		}
	}

	protected void processAbsoluteSymbols() throws Exception {
		monitor.setMessage("Processing absolute symbols...");
		List<NList> absoluteSymbols = new ArrayList<>();
		List<LoadCommand> commands = machoHeader.getLoadCommands();
		for (LoadCommand command : commands) {
			if (monitor.isCancelled()) {
				return;
			}
			if (!(command instanceof SymbolTableCommand)) {
				continue;
			}
			SymbolTableCommand symbolTableCommand = (SymbolTableCommand) command;
			List<NList> symbols = symbolTableCommand.getSymbols();
			for (NList symbol : symbols) {
				if (monitor.isCancelled()) {
					return;
				}
				if (symbol.isSymbolicDebugging()) {
					continue;
				}
				if (symbol.isTypeAbsolute()) {
					absoluteSymbols.add(symbol);
				}
			}
		}
		if (absoluteSymbols.size() == 0) {
			return;
		}
		Address start = getAddress();
		try {
			memory.createUninitializedBlock("ABSOLUTE", start,
				absoluteSymbols.size() * machoHeader.getAddressSize(), false);
		}
		catch (Exception e) {
			log.appendMsg("Unable to create absolute memory block: " + e.getMessage());
		}
		for (NList symbol : absoluteSymbols) {
			try {
				String name = SymbolUtilities.replaceInvalidChars(symbol.getString(), true);
				if (name != null && name.length() > 0) {
					program.getSymbolTable().createLabel(start, name, SourceType.IMPORTED);
				}
			}
			catch (Exception e) {
				log.appendMsg("Unable to create absolute symbol: " + e.getMessage());
			}
			start = start.add(machoHeader.getAddressSize());
		}
	}

	public List<Address> processChainedFixups(List<String> libraryPaths) throws Exception {
		monitor.setMessage("Fixing up chained pointers...");

		SymbolTable symbolTable = program.getSymbolTable();
		Address imagebase = getMachoBaseAddress();
		List<DyldFixup> fixups = new ArrayList<>();

		// First look for a DyldChainedFixupsCommand
		List<DyldChainedFixupsCommand> loadCommands =
			machoHeader.getLoadCommands(DyldChainedFixupsCommand.class);
		if (!loadCommands.isEmpty()) {
			for (DyldChainedFixupsCommand loadCommand : loadCommands) {
				fixups.addAll(loadCommand.getChainedFixups(reader, imagebase.getOffset(),
					symbolTable, log, monitor));
			}
		}
		else {
			// Didn't find a DyldChainedFixupsCommand, so look for the sections with fixup info
			Section chainStartsSection =
				machoHeader.getSection(SegmentNames.SEG_TEXT, SectionNames.CHAIN_STARTS);
			Section threadStartsSection =
				machoHeader.getSection(SegmentNames.SEG_TEXT, SectionNames.THREAD_STARTS);

			if (chainStartsSection != null) {
				reader.setPointerIndex(chainStartsSection.getOffset());
				DyldChainedStartsOffsets chainedStartsOffsets =
					new DyldChainedStartsOffsets(reader);
				for (int offset : chainedStartsOffsets.getChainStartOffsets()) {
					fixups.addAll(DyldChainedFixups.getChainedFixups(reader, null,
						chainedStartsOffsets.getPointerFormat(), offset, 0, 0,
						imagebase.getOffset(), symbolTable, log, monitor));
				}
			}
			else if (threadStartsSection != null) {
				Address threadSectionStart = space.getAddress(threadStartsSection.getAddress());
				Address threadSectionEnd =
					threadSectionStart.add(threadStartsSection.getSize() - 1);
				long nextOffSize = (memory.getInt(threadSectionStart) & 1) * 4 + 4;
				Address chainHead = threadSectionStart.add(4);
				while (chainHead.compareTo(threadSectionEnd) < 0 && !monitor.isCancelled()) {
					int headStartOffset = memory.getInt(chainHead);
					if (headStartOffset == 0xFFFFFFFF || headStartOffset == 0) {
						break;
					}
					long chainStart = Integer.toUnsignedLong(headStartOffset);
					fixups.addAll(DyldChainedFixups.processPointerChain(reader, chainStart,
						nextOffSize, imagebase.getOffset(), log, monitor));
					chainHead = chainHead.add(4);
				}
			}
		}

		return DyldChainedFixups.fixupChainedPointers(fixups, program, imagebase, libraryPaths,
			log, monitor);
	}

	protected void processDyldInfo(boolean doClassic, List<String> libraryPaths) throws Exception {

		List<DyldInfoCommand> commands = machoHeader.getLoadCommands(DyldInfoCommand.class);
		for (DyldInfoCommand command : commands) {
			processRebases(command.getRebaseTable());
			processBindings(command.getBindingTable(), libraryPaths);
			processBindings(command.getLazyBindingTable(), libraryPaths);
			processBindings(command.getWeakBindingTable(), libraryPaths);
		}

		if (commands.size() == 0 && doClassic) {
			ClassicBindProcessor classicBindProcess =
				new ClassicBindProcessor(machoHeader, program);
			try {
				classicBindProcess.process(monitor);
			}
			catch (Exception e) {
				log.appendException(e);
			}

			ClassicLazyBindProcessor classicLazyBindProcess =
				new ClassicLazyBindProcessor(machoHeader, program);
			try {
				classicLazyBindProcess.process(monitor);
			}
			catch (Exception e) {
				log.appendException(e);
			}
		}
	}

	private void processRebases(RebaseTable rebaseTable) throws Exception {
		// If we ever support rebasing a Mach-O at load time, this should get implemented
	}

	private void processBindings(BindingTable bindingTable, List<String> libraryPaths)
			throws Exception {
		DataConverter converter = DataConverter.getInstance(program.getLanguage().isBigEndian());
		SymbolTable symbolTable = program.getSymbolTable();
		Address imagebase = getMachoBaseAddress();

		List<Binding> bindings = bindingTable.getBindings();
		List<Binding> threadedBindings = bindingTable.getThreadedBindings();
		List<SegmentCommand> segments = machoHeader.getAllSegments();

		if (threadedBindings != null) {
			DyldChainedImports chainedImports = new DyldChainedImports(bindings);
			for (Binding threadedBinding : threadedBindings) {
				List<DyldFixup> fixups = DyldChainedFixups.getChainedFixups(reader,
					chainedImports, DyldChainType.DYLD_CHAINED_PTR_ARM64E,
					segments.get(threadedBinding.getSegmentIndex()).getFileOffset(),
					threadedBinding.getSegmentOffset(), 0, imagebase.getOffset(),
					symbolTable, log, monitor);
				DyldChainedFixups.fixupChainedPointers(fixups, program, imagebase, libraryPaths,
					log, monitor);
			}
		}
		else {
			for (Binding binding : bindings) {
				if (binding.getUnknownOpcode() != null) {
					log.appendMsg(
						"Unknown bind opcode: 0x%x".formatted(binding.getUnknownOpcode()));
					continue;
				}

				List<Symbol> symbols = symbolTable.getGlobalSymbols(binding.getSymbolName());
				if (symbols.isEmpty()) {
					continue;
				}
				Symbol symbol = symbols.get(0);
				long offset = symbol.getAddress().getOffset();
				byte[] bytes = (program.getDefaultPointerSize() == 8) ? converter.getBytes(offset)
						: converter.getBytes((int) offset);
				Address addr =
					space.getAddress(segments.get(binding.getSegmentIndex()).getVMaddress() +
						binding.getSegmentOffset());

				fixupExternalLibrary(binding.getLibraryOrdinal(), symbol, libraryPaths);

				boolean success = false;
				try {
					program.getMemory().setBytes(addr, bytes);
					success = true;
				}
				catch (MemoryAccessException e) {
					handleRelocationError(addr, String.format(
						"Relocation failure at address %s: error accessing memory.", addr));
				}
				finally {
					program.getRelocationTable()
							.add(addr, success ? Status.APPLIED_OTHER : Status.FAILURE,
								binding.getType(), null, bytes.length, binding.getSymbolName());
				}
			}
		}
	}

	private void fixupExternalLibrary(int libraryOrdinal, Symbol symbol, List<String> libraryPaths)
			throws InvalidInputException {
		ExternalManager extManager = program.getExternalManager();
		int libraryIndex = libraryOrdinal - 1;
		if (libraryIndex >= 0 && libraryIndex < libraryPaths.size()) {
			Library library = extManager.getExternalLibrary(libraryPaths.get(libraryIndex));
			ExternalLocation loc =
				extManager.getUniqueExternalLocation(Library.UNKNOWN, symbol.getName());
			if (loc != null) {
				loc.setName(library, symbol.getName(), SourceType.IMPORTED);
			}
		}
	}

	protected void markupHeaders(MachHeader header, Address headerAddr) throws Exception {
		monitor.setMessage("Processing header markup...");

		if (headerAddr == null) {
			return;
		}

		try {
			DataUtilities.createData(program, headerAddr, header.toDataType(), -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			for (LoadCommand loadCommand : header.getLoadCommands()) {
				if (monitor.isCancelled()) {
					break;
				}
				Address loadCommandAddr =
					headerAddr.add(loadCommand.getStartIndex() - header.getStartIndexInProvider());
				DataType loadCommandDataType = loadCommand.toDataType();
				DataUtilities.createData(program, loadCommandAddr, loadCommandDataType, -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				listing.setComment(loadCommandAddr, CodeUnit.PRE_COMMENT,
					LoadCommandTypes.getLoadCommandName(loadCommand.getCommandType()));

				if (loadCommand instanceof SegmentCommand) {
					SegmentCommand segmentCommand = (SegmentCommand) loadCommand;
					listing.setComment(loadCommandAddr, CodeUnit.EOL_COMMENT,
						segmentCommand.getSegmentName());

					int sectionOffset = loadCommandDataType.getLength();
					for (Section section : segmentCommand.getSections()) {
						DataType sectionDataType = section.toDataType();
						Address sectionAddr = loadCommandAddr.add(sectionOffset);
						DataUtilities.createData(program, sectionAddr, sectionDataType, -1,
							DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
						listing.setComment(sectionAddr, CodeUnit.EOL_COMMENT,
							section.getSegmentName() + "." + section.getSectionName());
						sectionOffset += sectionDataType.getLength();
					}
				}
				else if (loadCommand instanceof DynamicLinkerCommand) {
					DynamicLinkerCommand dynamicLinkerCommand = (DynamicLinkerCommand) loadCommand;
					LoadCommandString name = dynamicLinkerCommand.getLoadCommandString();
					DataUtilities.createData(program, loadCommandAddr.add(name.getOffset()),
						StructConverter.STRING, loadCommand.getCommandSize() - name.getOffset(),
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
				else if (loadCommand instanceof DynamicLibraryCommand) {
					DynamicLibraryCommand dynamicLibraryCommand =
						(DynamicLibraryCommand) loadCommand;
					LoadCommandString name = dynamicLibraryCommand.getDynamicLibrary().getName();
					DataUtilities.createData(program, loadCommandAddr.add(name.getOffset()),
						StructConverter.STRING, loadCommand.getCommandSize() - name.getOffset(),
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
				else if (loadCommand instanceof RunPathCommand) {
					RunPathCommand runPathCommand = (RunPathCommand) loadCommand;
					LoadCommandString path = runPathCommand.getPath();
					DataUtilities.createData(program, loadCommandAddr.add(path.getOffset()),
						StructConverter.STRING, loadCommand.getCommandSize() - path.getOffset(),
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
				else if (loadCommand instanceof SubFrameworkCommand) {
					SubFrameworkCommand subFrameworkCommand = (SubFrameworkCommand) loadCommand;
					LoadCommandString name = subFrameworkCommand.getUmbrellaFrameworkName();
					DataUtilities.createData(program, loadCommandAddr.add(name.getOffset()),
						StructConverter.STRING, loadCommand.getCommandSize() - name.getOffset(),
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
				else if (loadCommand instanceof SubClientCommand) {
					SubClientCommand subClientCommand = (SubClientCommand) loadCommand;
					LoadCommandString name = subClientCommand.getClientName();
					DataUtilities.createData(program, loadCommandAddr.add(name.getOffset()),
						StructConverter.STRING, loadCommand.getCommandSize() - name.getOffset(),
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
				else if (loadCommand instanceof SubLibraryCommand) {
					SubLibraryCommand subLibraryCommand = (SubLibraryCommand) loadCommand;
					LoadCommandString name = subLibraryCommand.getSubLibraryName();
					DataUtilities.createData(program, loadCommandAddr.add(name.getOffset()),
						StructConverter.STRING, loadCommand.getCommandSize() - name.getOffset(),
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
				else if (loadCommand instanceof SubUmbrellaCommand) {
					SubUmbrellaCommand subUmbrellaCommand = (SubUmbrellaCommand) loadCommand;
					LoadCommandString name = subUmbrellaCommand.getSubUmbrellaFrameworkName();
					DataUtilities.createData(program, loadCommandAddr.add(name.getOffset()),
						StructConverter.STRING, loadCommand.getCommandSize() - name.getOffset(),
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
					DataUtilities.createData(program, loadCommandAddr.add(name.getOffset()),
						StructConverter.STRING, loadCommand.getCommandSize() - name.getOffset(),
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
				else if (loadCommand instanceof FileSetEntryCommand) {
					FileSetEntryCommand fileSetEntryCommand = (FileSetEntryCommand) loadCommand;
					LoadCommandString name = fileSetEntryCommand.getFileSetEntryId();
					DataUtilities.createData(program, loadCommandAddr.add(name.getOffset()),
						StructConverter.STRING, loadCommand.getCommandSize() - name.getOffset(),
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
				else if (loadCommand instanceof LinkerOptionCommand) {
					LinkerOptionCommand linkerOptionCommand = (LinkerOptionCommand) loadCommand;
					List<String> linkerOptions = linkerOptionCommand.getLinkerOptions();
					int offset = linkerOptionCommand.toDataType().getLength();
					for (int i = 0; i < linkerOptions.size(); i++) {
						Address addr = loadCommandAddr.add(offset);
						int len = linkerOptions.get(i).length() + 1;
						if (i == linkerOptions.size() - 1) {
							len = (int) (NumericUtilities.getUnsignedAlignedValue(
								addr.add(len).getOffset(), 4) - addr.getOffset());
						}
						DataUtilities.createData(program, addr, StructConverter.STRING, len,
							DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
						offset += len;
					}
				}
			}
		}
		catch (CodeUnitInsertionException e) {
			log.appendMsg("Error laying down header structures " + e);
		}

	}

	/**
	 * Sets up the {@link MachHeader} in memory and returns its address.  If the header was not 
	 * intended to reside in memory (like for Mach-O object files), then this method will create an
	 * area in the "OTHER" address space for the header to live in.
	 * 
	 * @param segments A {@link Collection} of {@link SegmentCommand Mach-O segments}
	 * @return The {@link Address} of {@link MachHeader} in memory
	 * @throws AddressOverflowException if the address lies outside the address space
	 */
	protected Address setupHeaderAddr(Collection<SegmentCommand> segments)
			throws AddressOverflowException {
		Address headerAddr = null;
		long lowestFileOffset = Long.MAX_VALUE;

		// Check to see if the header resides in an existing segment.  If it does, we know its
		// address and we are done.  Keep track of the lowest file offset for later use.
		for (SegmentCommand segment : segments) {
			if (segment.getFileOffset() == 0 && segment.getFileSize() == 0) {
				// Don't consider empty segments (seen in .dSYM/DWARF files)
				continue;
			}
			if (segment.getFileOffset() == 0) {
				return space.getAddress(segment.getVMaddress());
			}
			lowestFileOffset = Math.min(lowestFileOffset, segment.getFileOffset());
		}

		// The header did not live in a defined segment.  Create a memory region in the OTHER space 
		// and copy the header there.
		headerAddr = AddressSpace.OTHER_SPACE.getAddress(0);
		MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true, "HEADER",
			headerAddr, fileBytes, 0, lowestFileOffset, "Header", "", false, false, false, log);
		return headerBlock.getStart();
	}

	protected void markupSections() throws Exception {

		monitor.setMessage("Processing section markup...");

		if (machoHeader.getFileType() == MachHeaderFileTypes.MH_DYLIB_STUB) {
			return;
		}

		for (SegmentCommand segment : machoHeader.getAllSegments()) {

			if (monitor.isCancelled()) {
				break;
			}

			// do not markup sections that are encrypted
			if (segment.isAppleProtected()) {
				String msg = "Warning:  " + program.getName() + " contains encrypted segment: " +
					segment.getSegmentName();
				log.appendMsg(msg);
				Msg.showWarn(this, null, "Encrypted Binary", msg);
				continue;
			}

			List<Section> sections = segment.getSections();

			for (Section section : sections) {

				if (monitor.isCancelled()) {
					break;
				}

				if (section.getSize() == 0) {
					continue;
				}

				MemoryBlock block = getMemoryBlock(section);

				if (block == null) {
					continue;
				}

				if (section.getSectionName().equals(SectionNames.CHAIN_STARTS)) {
					reader.setPointerIndex(section.getOffset());
					DyldChainedStartsOffsets chainedStartsOffsets =
						new DyldChainedStartsOffsets(reader);
					DataUtilities.createData(program, block.getStart(),
						chainedStartsOffsets.toDataType(), -1,
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
				else if (section.getType() == SectionTypes.S_CSTRING_LITERALS) {
					markupBlock(block, new TerminatedStringDataType());
				}
				else if (section.getType() == SectionTypes.S_4BYTE_LITERALS) {
					markupBlock(block, new FloatDataType());
				}
				else if (section.getType() == SectionTypes.S_8BYTE_LITERALS) {
					markupBlock(block, new DoubleDataType());
				}
				else if (section.getType() == SectionTypes.S_LITERAL_POINTERS) {
					markupBlock(block, new PointerDataType());
				}
				else if (section.getType() == SectionTypes.S_NON_LAZY_SYMBOL_POINTERS ||
					section.getType() == SectionTypes.S_LAZY_SYMBOL_POINTERS) {
					markupBlock(block, new PointerDataType());
				}
				else if (section.getType() == SectionTypes.S_SYMBOL_STUBS && section.isExecute()) {
					// TODO should we disassemble?? see iMovieHD.80386
					// disassemble(program, block, monitor);
				}

				if (section.getType() == SectionTypes.S_LAZY_SYMBOL_POINTERS) {
					AddressSetView set = new AddressSet(block.getStart(), block.getEnd());
					processLazyPointerSection(set);
				}
			}
		}
	}

	/**
	 * Processes the section relocations from all {@link Section}s.
	 * 
	 * @throws CancelledException if the operation was cancelled.
	 */
	protected void processSectionRelocations() throws CancelledException {
		monitor.setMessage("Processing section relocations...");

		LinkedHashMap<RelocationInfo, Address> relocationMap = new LinkedHashMap<>();
		for (Section section : machoHeader.getAllSections()) {
			monitor.checkCancelled();

			MemoryBlock sectionMemoryBlock = getMemoryBlock(section);
			if (sectionMemoryBlock == null) {
				if (section.getNumberOfRelocations() > 0) {
					log.appendMsg("Unable to process relocations for " + section.getSectionName() +
						". No memory block was created.");
				}
				continue;
			}

			for (RelocationInfo relocationInfo : section.getRelocations()) {
				monitor.checkCancelled();
				Address address = sectionMemoryBlock.getStart().add(relocationInfo.getAddress());
				relocationMap.put(relocationInfo, address);
			}
		}
		performRelocations(relocationMap);
	}

	/**
	 * Processes the external relocations from all {@link DynamicSymbolTableCommand}s.
	 * 
	 * @throws CancelledException if the operation was cancelled.
	 */
	protected void processExternalRelocations() throws CancelledException {

		monitor.setMessage("Processing external relocations...");

		LinkedHashMap<RelocationInfo, Address> relocationMap = new LinkedHashMap<>();
		for (DynamicSymbolTableCommand cmd : machoHeader
				.getLoadCommands(DynamicSymbolTableCommand.class)) {
			monitor.checkCancelled();
			for (RelocationInfo relocationInfo : cmd.getExternalRelocations()) {
				monitor.checkCancelled();
				relocationMap.put(relocationInfo, space.getAddress(relocationInfo.getAddress()));
			}
		}
		performRelocations(relocationMap);
	}

	/**
	 * Processes the local relocations from all {@link DynamicSymbolTableCommand}s.
	 * 
	 * @throws CancelledException if the operation was cancelled.
	 */
	protected void processLocalRelocations() throws CancelledException {

		monitor.setMessage("Processing local relocations...");

		LinkedHashMap<RelocationInfo, Address> relocationMap = new LinkedHashMap<>();
		for (DynamicSymbolTableCommand cmd : machoHeader
				.getLoadCommands(DynamicSymbolTableCommand.class)) {
			monitor.checkCancelled();
			for (RelocationInfo relocationInfo : cmd.getLocalRelocations()) {
				monitor.checkCancelled();
				relocationMap.put(relocationInfo, space.getAddress(relocationInfo.getAddress()));
			}
		}
		performRelocations(relocationMap);
	}

	protected List<String> processLibraries() throws Exception {
		monitor.setMessage("Processing libraries...");

		Options props = program.getOptions(Program.PROGRAM_INFO);
		int libraryIndex = 0;
		List<String> libraryPaths = new ArrayList<>();

		for (LoadCommand command : machoHeader.getLoadCommands()) {
			if (monitor.isCancelled()) {
				return libraryPaths;
			}

			String libraryPath = null;

			if (command instanceof DynamicLibraryCommand dylibCommand) {
				DynamicLibrary dylib = dylibCommand.getDynamicLibrary();
				libraryPath = dylib.getName().getString();
			}
			else if (command instanceof SubLibraryCommand sublibCommand) {
				libraryPath = sublibCommand.getSubLibraryName().getString();
			}
			else if (command instanceof PreboundDynamicLibraryCommand pbdlCommand) {
				libraryPath = pbdlCommand.getLibraryName();
			}

			if (libraryPath != null) {
				int index = libraryPath.lastIndexOf("/");
				String libraryName = index != -1 ? libraryPath.substring(index + 1) : libraryPath;
				if (!libraryName.equals(program.getName())) {
					libraryPaths.add(libraryPath);
					addLibrary(libraryPath);
					props.setString(
						ExternalSymbolResolver.getRequiredLibraryProperty(libraryIndex++),
						libraryPath);
				}
			}
		}

		if (program.getSymbolTable().getLibrarySymbol(Library.UNKNOWN) == null) {
			program.getSymbolTable().createExternalLibrary(Library.UNKNOWN, SourceType.IMPORTED);
		}

		return libraryPaths;
	}

	/**
	 * Logs encrypted block ranges
	 * 
	 * @throws Exception if there was a problem detecting the encrypted block ranges
	 */
	protected void processEncryption() throws Exception {
		monitor.setMessage("Processing encryption...");
		for (EncryptedInformationCommand cmd : machoHeader
				.getLoadCommands(EncryptedInformationCommand.class)) {
			if (cmd.getCryptID() != 0) {
				log.appendMsg(String.format("ENCRYPTION DETECTED: (file offset 0x%x, size 0x%x)",
					cmd.getCryptOffset(), cmd.getCryptSize()));
			}
		}
	}

	/**
	 * Processes {@link LoadCommand}s that we haven't implemented yet.
	 * 
	 * @throws CancelledException if the operation was cancelled.
	 */
	protected void processUnsupportedLoadCommands() throws CancelledException {
		monitor.setMessage("Processing unsupported load commands...");

		for (LoadCommand cmd : machoHeader.getLoadCommands(UnsupportedLoadCommand.class)) {
			monitor.checkCancelled();
			log.appendMsg("Skipping unsupported load command: " +
				LoadCommandTypes.getLoadCommandName(cmd.getCommandType()));
		}
	}

	/**
	 * Processes {@link LoadCommand}s that appear to be corrupt.
	 * 
	 * @throws CancelledException if the operation was cancelled.
	 */
	protected void processCorruptLoadCommands() throws CancelledException {
		monitor.setMessage("Processing corrupt load commands...");

		for (CorruptLoadCommand cmd : machoHeader.getLoadCommands(CorruptLoadCommand.class)) {
			monitor.checkCancelled();
			log.appendMsg("Skipping corrupt load command: %s (%s: %s)".formatted(
				LoadCommandTypes.getLoadCommandName(cmd.getCommandType()),
				cmd.getProblem().getClass().getSimpleName(),
				cmd.getProblem().getMessage()));
		}
	}

	/**
	 * Performs the given relocations.
	 * 
	 * @param relocationMap The relocations to perform, mapped to the addresses they should get
	 *   performed at.  The relocations must be performed in their supplied order.
	 * @throws CancelledException if the operation was cancelled.
	 */
	private void performRelocations(LinkedHashMap<RelocationInfo, Address> relocationMap)
			throws CancelledException {

		if (relocationMap.isEmpty()) {
			return;
		}

		MachoRelocationHandler handler = MachoRelocationHandlerFactory.getHandler(machoHeader);
		if (handler == null) {
			log.appendMsg(String.format("No relocation handler for machine type 0x%x",
				machoHeader.getCpuType()));
		}

		Iterator<RelocationInfo> iter = relocationMap.keySet().iterator();
		while (iter.hasNext()) {
			RelocationInfo relocationInfo = iter.next();
			Address address = relocationMap.get(relocationInfo);
			MachoRelocation relocation = null;

			RelocationResult result = RelocationResult.FAILURE;
			if (handler != null) {
				relocation = handler.isPairedRelocation(relocationInfo)
						? new MachoRelocation(program, machoHeader, address, relocationInfo,
							iter.next())
						: new MachoRelocation(program, machoHeader, address, relocationInfo);
				try {
					result = handler.relocate(relocation);

					if (result.status() == Status.UNSUPPORTED) {
						handleRelocationError(address,
							String.format("Relocation type 0x%x at address %s is not supported",
								relocationInfo.getType(), address));
					}
				}
				catch (MemoryAccessException e) {
					handleRelocationError(address, String.format(
						"Relocation failure at address %s: error accessing memory.", address));
				}
				catch (RelocationException e) {
					handleRelocationError(address, String.format(
						"Relocation failure at address %s: %s", address, e.getMessage()));
				}
				catch (Exception e) { // handle unexpected exceptions
					String msg = e.getMessage();
					if (msg == null) {
						msg = e.toString();
					}
					msg = String.format("Relocation failure at address %s: %s", address, msg);
					handleRelocationError(address, msg);
					Msg.error(this, msg, e);
				}
			}
			program.getRelocationTable()
					.add(address, result.status(), relocationInfo.getType(),
						new long[] { relocationInfo.getValue(), relocationInfo.getLength(),
							relocationInfo.isPcRelocated() ? 1 : 0,
							relocationInfo.isExternal() ? 1 : 0,
							relocationInfo.isScattered() ? 1 : 0 },
						result.byteLength(),
						relocation != null ? relocation.getTargetDescription() : null);
		}
	}

	/**
	 * Marks up {@link LoadCommand} dadta
	 * 
	 * @param header The Mach-O header
	 * @param source A name that represents where the header came from (could be null)
	 * @throws Exception If there was a problem performing the markup
	 */
	protected void markupLoadCommandData(MachHeader header, String source) throws Exception {
		for (LoadCommand cmd : header.getLoadCommands()) {
			cmd.markup(program, header, source, monitor, log);
		}
	}

	/**
	 * Handles a relocation error by placing a bookmark and writing to the log
	 * 
	 * @param address The address of the relocation error
	 * @param message The error message
	 */
	private void handleRelocationError(Address address, String message) {
		program.getBookmarkManager()
				.setBookmark(address, BookmarkType.ERROR, "Relocations", message);
		log.appendMsg(message);
	}

	private void addLibrary(String library) {
		library = library.replaceAll(" ", "_");
		try {
			program.getExternalManager().addExternalLibraryName(library, SourceType.IMPORTED);
		}
		catch (DuplicateNameException e) {
			// do not care
		}
		catch (Exception e) {
			log.appendMsg("Unable to add external library name: " + e.getMessage());
		}
	}

	private Address getAddress() {
		Address maxAddress = null;
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.isOverlay()) {
				continue;
			}
			if (maxAddress == null || block.getEnd().compareTo(maxAddress) > 0) {
				maxAddress = block.getEnd();
			}
		}
		if (maxAddress == null) {
			return space.getAddress(0x1000);
		}
		long maxAddr = maxAddress.getOffset();
		long remainder = maxAddr % 0x1000;
		return maxAddress.getNewAddress(maxAddr + 0x1000 - remainder);
	}

	private MemoryBlock getMemoryBlock(Section section) {
		Address blockAddress = space.getAddress(section.getAddress());
		return memory.getBlock(blockAddress);
	}

	private void markupBlock(MemoryBlock block, DataType datatype) throws Exception {
		Address address = block.getStart();
		while (!monitor.isCancelled()) {
			if (address.compareTo(block.getEnd()) > 0) {
				break;
			}
			try {
				listing.createData(address, datatype);
				if (datatype instanceof Pointer) {
					fixupThumbPointers(address);
				}
				address = address.add(listing.getDataAt(address).getLength());
			}
			catch (CodeUnitInsertionException e) {
				if (datatype instanceof TerminatedStringDataType) {
					// Sometimes there are huge strings, like JSON blobs
					log.appendMsg("Skipping markup for large string at: " + address);
				}
				else if (!(datatype instanceof Pointer)) {
					// May have already been created, by relocation, or chain pointers
					log.appendMsg("Skipping markup for existing pointer at: " + address);
				}
				else {
					log.appendException(e);
				}
				return;
			}
			catch (Exception e) {
				log.appendException(e);
				return;
			}
		}
	}

	/**
	 * To indicate a pointer to THUMB code, the compiler generates an address
	 * that is 1 more than the actual destination. For example, a pointer to
	 * THUMB code at 0x1000 would be generated as 0x1001. We detect this case
	 * and correct the pointer reference so that Ghidra will disassemble
	 * correctly.
	 *
	 * We also need to set the TMode bit!
	 * @param address the address
	 * @throws AddressOverflowException if there was a problem
	 */
	private void fixupThumbPointers(Address address) throws AddressOverflowException {
		Data data = listing.getDefinedDataAt(address);
		if (data == null) {
			return;
		}

		Object value = data.getValue();
		if (!(value instanceof Address)) {
			return;
		}

		Address pointerAddress = (Address) value;
		if ((pointerAddress.getOffset() % 2) == 0) {// is the pointer an EVEN
			// value?
			return;
		}

		MemoryBlock pointerBlock = memory.getBlock(pointerAddress);
		if (pointerBlock == null) {
			return;
		}
		if (!pointerBlock.isExecute()) {
			return;//not pointing to code....
		}

		Reference[] refs = data.getReferencesFrom();

		ReferenceManager referenceManager = program.getReferenceManager();
		for (Reference ref : refs) {
			if (monitor.isCancelled()) {
				break;
			}

			if (ref.getToAddress().equals(pointerAddress)) {
				referenceManager.delete(ref);

				Address thumbAddress = ref.getToAddress().subtract(1);
				referenceManager.addMemoryReference(ref.getFromAddress(), thumbAddress,
					ref.getReferenceType(), ref.getSource(), ref.getOperandIndex());
				try {
					markAsThumb(thumbAddress);
				}
				catch (ContextChangeException e) {
					// ignore since no instruction should exist at time of import
				}
			}
		}
	}

	private void markAsThumb(Address address)
			throws ContextChangeException, AddressOverflowException {
		if (!program.getLanguage()
				.getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor("ARM"))) {
			return;
		}
		if ((address.getOffset() & 1) == 1) {
			address = address.subtractNoWrap(1);
		}
		Register tModeRegister = program.getLanguage().getRegister("TMode");
		program.getProgramContext().setValue(tModeRegister, address, address, BigInteger.ONE);
		createOneByteFunction(null, address);
	}

	private void processLazyPointerSection(AddressSetView set) {
		DataIterator dataIterator = listing.getData(set, true);
		while (dataIterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			Data data = dataIterator.next();
			Reference[] references = data.getReferencesFrom();
			for (Reference reference : references) {
				if (monitor.isCancelled()) {
					break;
				}
				Symbol fromSymbol =
					program.getSymbolTable().getPrimarySymbol((reference.getFromAddress()));
				try {
					MemoryBlock memoryBlock = memory.getBlock(reference.getToAddress());
					Namespace namespace = createNamespace(memoryBlock.getName());
					program.getSymbolTable()
							.createLabel(reference.getToAddress(), fromSymbol.getName(), namespace,
								SourceType.IMPORTED);
				}
				catch (Exception e) {
					//log.appendMsg("Unable to create lazy pointer symbol " + fromSymbol.getName() + " at " + reference.getToAddress());
					//log.appendException(e);
				}
			}
		}
	}

	protected Namespace createNamespace(String namespaceName) {
		try {
			return program.getSymbolTable()
					.createNameSpace(program.getGlobalNamespace(), namespaceName,
						SourceType.IMPORTED);
		}
		catch (DuplicateNameException | InvalidInputException e) {
			Namespace namespace =
				program.getSymbolTable().getNamespace(namespaceName, program.getGlobalNamespace());
			if (namespace != null) {
				return namespace;
			}
			log.appendMsg("Unable to create namespace: " + namespaceName);
			log.appendException(e);
		}
		return program.getGlobalNamespace();
	}

	/**
	 * create a one-byte function, so that when the code is analyzed,
	 * it will be disassembled, and the function created with the correct body.
	 *
	 * @param name the name of the function
	 * @param address location to create the function
	 * @return If a function already existed at the given address, that function will be returned.
	 *   Otherwise, the newly created function will be returned.  If there was a problem creating
	 *   the function, null will be returned.
	 */
	Function createOneByteFunction(String name, Address address) {
		FunctionManager functionMgr = program.getFunctionManager();
		Function function = functionMgr.getFunctionAt(address);
		if (function != null) {
			return function;
		}
		try {
			return functionMgr.createFunction(name, address, new AddressSet(address),
				SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			// ignore
		}
		catch (OverlappingFunctionException e) {
			// ignore
		}
		return null;
	}

	/**
	 * Markup the given {@link List} of chained fixups by creating pointers at their locations,
	 * if possible
	 * 
	 * @param header The Mach-O header
	 * @param chainedFixups  The {@link List} of chained fixups to markup
	 * @throws CancelledException if the operation was cancelled
	 */
	protected void markupChainedFixups(MachHeader header, List<Address> chainedFixups)
			throws CancelledException {
		for (Address addr : chainedFixups) {
			monitor.checkCancelled();
			try {
				listing.createData(addr, PointerDataType.dataType);
			}
			catch (CodeUnitInsertionException e) {
				// No worries, something presumably more important was there already
			}
		}
	}

	/**
	 * See crt.c from opensource.apple.com
	 */
	protected void markupProgramVars() {
		if (program.getLanguage().getProcessor() == Processor
				.findOrPossiblyCreateProcessor("PowerPC")) {
			return;
		}

		SymbolTable symbolTable = program.getSymbolTable();

		int defaultPointerSize = program.getDefaultPointerSize();

		DataType intDataType =
			(defaultPointerSize == 8) ? new QWordDataType() : new DWordDataType();
		DataType intPointerDataType = PointerDataType.getPointer(intDataType, defaultPointerSize);//int *
		DataType voidPointerDatatype =
			PointerDataType.getPointer(new VoidDataType(), defaultPointerSize);//void *
		DataType charPointerX1DataType =
			PointerDataType.getPointer(new CharDataType(), defaultPointerSize);//char *
		DataType charPointerX2DataType =
			PointerDataType.getPointer(charPointerX1DataType, defaultPointerSize);//char **
		DataType charPointerX3DataType =
			PointerDataType.getPointer(charPointerX2DataType, defaultPointerSize);//char ***

		Structure structure = new StructureDataType(SectionNames.PROGRAM_VARS, 0);
		structure.add(voidPointerDatatype, "mh", "pointer to __mh_execute_header");
		structure.add(intPointerDataType, "NXArgcPtr", "pointer to argc");
		structure.add(charPointerX3DataType, "NXArgvPtr", "pointer to argv");
		structure.add(charPointerX3DataType, "environPtr", "pointer to environment");
		structure.add(charPointerX2DataType, "__prognamePtr", "pointer to program name");

		Namespace namespace = createNamespace(SectionNames.PROGRAM_VARS);

		List<Section> sections = machoHeader.getAllSections();
		for (Section section : sections) {
			if (section.getSectionName().equals(SectionNames.PROGRAM_VARS)) {
				MemoryBlock memoryBlock = getMemoryBlock(section);
				try {
					listing.createData(memoryBlock.getStart(), structure);
					Data data = listing.getDataAt(memoryBlock.getStart());

					Data mhData = data.getComponent(0);
					if (symbolTable.getSymbol("__mh_execute_header", mhData.getAddress(0),
						namespace) == null) {
						symbolTable.createLabel(mhData.getAddress(0), "__mh_execute_header",
							namespace, SourceType.IMPORTED);
					}

					Data argcData = data.getComponent(1);
					symbolTable.createLabel(argcData.getAddress(0), "NXArgc", namespace,
						SourceType.IMPORTED);
					listing.createData(argcData.getAddress(0), intDataType);

					Data argvData = data.getComponent(2);
					symbolTable.createLabel(argvData.getAddress(0), "NXArgv", namespace,
						SourceType.IMPORTED);
					listing.createData(argvData.getAddress(0), charPointerX2DataType);

					Data environData = data.getComponent(3);
					symbolTable.createLabel(environData.getAddress(0), "environ", namespace,
						SourceType.IMPORTED);
					listing.createData(environData.getAddress(0), charPointerX2DataType);

					Data prognameData = data.getComponent(4);
					symbolTable.createLabel(prognameData.getAddress(0), "__progname", namespace,
						SourceType.IMPORTED);
					listing.createData(prognameData.getAddress(0), charPointerX1DataType);
				}
				catch (Exception e) {
					log.appendException(e);
					return;
				}
			}
		}
	}

	protected void setRelocatableProperty() {
		Options props = program.getOptions(Program.PROGRAM_INFO);
		switch (machoHeader.getFileType()) {
			case MachHeaderFileTypes.MH_EXECUTE:
				props.setBoolean(RelocationTable.RELOCATABLE_PROP_NAME, false);
				break;
			default:
				props.setBoolean(RelocationTable.RELOCATABLE_PROP_NAME, true);
				break;
		}
	}

	protected void setProgramDescription() {
		Options props = program.getOptions(Program.PROGRAM_INFO);
		props.setString("Mach-O File Type",
			MachHeaderFileTypes.getFileTypeName(machoHeader.getFileType()));
		props.setString("Mach-O File Type Description",
			MachHeaderFileTypes.getFileTypeDescription(machoHeader.getFileType()));
		List<String> flags = MachHeaderFlags.getFlags(machoHeader.getFlags());
		for (int i = 0; i < flags.size(); ++i) {
			props.setString("Mach-O Flag " + i, flags.get(i));
		}

		List<SubUmbrellaCommand> umbrellas = machoHeader.getLoadCommands(SubUmbrellaCommand.class);
		for (int i = 0; i < umbrellas.size(); ++i) {
			props.setString("Mach-O Sub-umbrella " + i,
				umbrellas.get(i).getSubUmbrellaFrameworkName().getString());
		}

		List<SubFrameworkCommand> frameworks =
			machoHeader.getLoadCommands(SubFrameworkCommand.class);
		for (int i = 0; i < frameworks.size(); ++i) {
			props.setString("Mach-O Sub-framework " + i,
				frameworks.get(i).getUmbrellaFrameworkName().getString());
		}
	}

	protected void markupAndSetGolangInitialProgramProperties() {
		ItemWithAddress<GoBuildId> buildId = GoBuildId.findBuildId(program);
		if (buildId != null) {
			buildId.item().markupProgram(program, buildId.address());
		}
		ItemWithAddress<GoBuildInfo> buildInfo = GoBuildInfo.findBuildInfo(program);
		if (buildInfo != null) {
			buildInfo.item().markupProgram(program, buildInfo.address());
		}
	}

	protected void setCompiler() {
		// Check for Rust
		try {
			SegmentCommand segment = machoHeader.getSegment(SegmentNames.SEG_TEXT);
			if (segment == null) {
				return;
			}
			Section section = segment.getSectionByName(SectionNames.TEXT_CONST);
			if (section == null) {
				return;
			}
			if (RustUtilities.isRust(memory.getBlock(space.getAddress(section.getAddress())))) {
				program.setCompiler(RustConstants.RUST_COMPILER);
				int extensionCount = RustUtilities.addExtensions(program, monitor,
					RustConstants.RUST_EXTENSIONS_UNIX);
				log.appendMsg("Installed " + extensionCount + " Rust cspec extensions");
			}
		}
		catch (IOException e) {
			log.appendMsg("Rust error: " + e.getMessage());
		}
	}

	protected void renameObjMsgSendRtpSymbol()
			throws DuplicateNameException, InvalidInputException {
		Address address = space.getAddress(ObjectiveC1_Constants.OBJ_MSGSEND_RTP);
		Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
		if (symbol != null && symbol.isDynamic()) {
			symbol.setName(ObjectiveC1_Constants.OBJC_MSG_SEND_RTP_NAME, SourceType.IMPORTED);
		}
		else {
			program.getSymbolTable()
					.createLabel(address, ObjectiveC1_Constants.OBJC_MSG_SEND_RTP_NAME,
						SourceType.IMPORTED);
		}
	}
}

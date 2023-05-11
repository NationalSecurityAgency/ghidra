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

import static ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.*;

import java.math.BigInteger;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.RelocationException;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.app.util.bin.format.macho.commands.ExportTrie.ExportEntry;
import ghidra.app.util.bin.format.macho.commands.dyld.*;
import ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr;
import ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.DyldChainType;
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
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
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
	protected boolean shouldAddChainedFixupsRelocations;
	protected MessageLog log;
	protected TaskMonitor monitor;
	protected Memory memory;
	protected Listing listing;
	protected AddressSpace space;

	/**
	 * Creates a new {@link MachoProgramBuilder} based on the given information.
	 * 
	 * @param program The {@link Program} to build up.
	 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
	 * @param fileBytes Where the Mach-O's bytes came from.
	 * @param shouldAddChainedFixupsRelocations True if relocations should be added for chained 
	 *   fixups; otherwise, false.
	 * @param log The log.
	 * @param monitor A cancelable task monitor.
	 */
	protected MachoProgramBuilder(Program program, ByteProvider provider, FileBytes fileBytes,
			boolean shouldAddChainedFixupsRelocations, MessageLog log, TaskMonitor monitor) {
		this.program = program;
		this.provider = provider;
		this.fileBytes = fileBytes;
		this.shouldAddChainedFixupsRelocations = shouldAddChainedFixupsRelocations;
		this.log = log;
		this.monitor = monitor;
		this.memory = program.getMemory();
		this.listing = program.getListing();
		this.space = program.getAddressFactory().getDefaultAddressSpace();
	}

	/**
	 * Builds up a Mach-O {@link Program}.
	 * 
	 * @param program The {@link Program} to build up.
	 * @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
	 * @param fileBytes Where the Mach-O's bytes came from.
	 * @param addChainedFixupsRelocations True if relocations should be added for chained fixups;
	 *   otherwise, false.
	 * @param log The log.
	 * @param monitor A cancelable task monitor.
	 * @throws Exception if a problem occurs.
	 */
	public static void buildProgram(Program program, ByteProvider provider, FileBytes fileBytes,
			boolean addChainedFixupsRelocations, MessageLog log, TaskMonitor monitor)
			throws Exception {
		MachoProgramBuilder machoProgramBuilder = new MachoProgramBuilder(program, provider,
			fileBytes, addChainedFixupsRelocations, log, monitor);
		machoProgramBuilder.build();
	}

	protected void build() throws Exception {

		monitor.setMessage("Completing Mach-O header parsing...");
		monitor.setCancelEnabled(false);
		machoHeader = new MachHeader(provider);
		machoHeader.parse();
		monitor.setCancelEnabled(true);

		setImageBase();
		processEncryption();
		processEntryPoint();
		processMemoryBlocks(machoHeader, provider.getName(), true, true);
		fixupProgramTree();
		processUnsupportedLoadCommands();
		boolean exportsFound = processExports(machoHeader);
		processSymbolTables(machoHeader, !exportsFound);
		setRelocatableProperty();
		processLibraries();
		processProgramDescription();
		renameObjMsgSendRtpSymbol();
		processUndefinedSymbols();
		processAbsoluteSymbols();
		List<Address> chainedFixups = processChainedFixups();
		processBindings(false);
		markupHeaders(machoHeader, setupHeaderAddr(machoHeader.getAllSegments()));
		markupSections();
		processProgramVars();
		processSectionRelocations();
		processExternalRelocations();
		processLocalRelocations();
		markupChainedFixups(chainedFixups);
	}

	/**
	 * Sets the image base
	 * 
	 * @throws Exception if there was a problem setting the image base
	 */
	protected void setImageBase() throws Exception {
		Address imageBaseAddr = null;
		for (SegmentCommand segment : machoHeader.getAllSegments()) {
			if (segment.getFileSize() > 0) {
				Address segmentAddr = space.getAddress(segment.getVMaddress());
				if (imageBaseAddr == null) {
					imageBaseAddr = segmentAddr;
				}
				else if (segmentAddr.compareTo(imageBaseAddr) < 0) {
					imageBaseAddr = segmentAddr;
				}
			}
		}
		if (imageBaseAddr != null) {
			program.setImageBase(imageBaseAddr, true);
		}
		else {
			program.setImageBase(space.getAddress(0), true);
		}
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
 	 * Attempts to discover and set the entry point.
 	 * 
 	 * @throws Exception If there was a problem discovering or setting the entry point.
 	 */
	protected void processEntryPoint() throws Exception {
		monitor.setMessage("Processing entry point...");
		Address entryPointAddr = null;

		EntryPointCommand entryPointCommand =
			machoHeader.getFirstLoadCommand(EntryPointCommand.class);
		if (entryPointCommand != null) {
			long offset = entryPointCommand.getEntryOffset();
			if (offset > 0) {
				SegmentCommand segment = machoHeader.getSegment("__TEXT");
				if (segment != null) {
					entryPointAddr = space.getAddress(segment.getVMaddress()).add(offset);
				}
			}
		}

		if (entryPointAddr == null) {
			ThreadCommand threadCommand = machoHeader.getFirstLoadCommand(ThreadCommand.class);
			if (threadCommand != null) {
				long pointer = threadCommand.getInitialInstructionPointer();
				if (pointer != -1) {
					entryPointAddr = space.getAddress(pointer);
				}
			}
		}

		if (entryPointAddr != null) {
			program.getSymbolTable().createLabel(entryPointAddr, "entry", SourceType.IMPORTED);
			program.getSymbolTable().addExternalEntryPoint(entryPointAddr);
			createOneByteFunction("entry", entryPointAddr);
		}
		else {
			log.appendMsg("Unable to determine entry point.");
		}
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

		// Create memory blocks for segments.
		ListIterator<SegmentCommand> it = header.getAllSegments().listIterator();
		while (it.hasNext()) {
			int i = it.nextIndex();
			final SegmentCommand segment = it.next();

			if (monitor.isCancelled()) {
				break;
			}

			if (segment.getFileSize() > 0 && (allowZeroAddr || segment.getVMaddress() != 0)) {
				String segmentName = segment.getSegmentName();
				if (segmentName.isBlank()) {
					segmentName = "SEGMENT." + i;
				}
				if (createMemoryBlock(segmentName, space.getAddress(segment.getVMaddress()),
					segment.getFileOffset(), segment.getFileSize(), segmentName, source,
					segment.isRead(), segment.isWrite(), segment.isExecute(), false) == null) {
					log.appendMsg(String.format("Failed to create block: %s 0x%x 0x%x",
						segment.getSegmentName(), segment.getVMaddress(), segment.getVMsize()));
				}
				if (segment.getVMsize() > segment.getFileSize()) {
					// Pad the remaining address range with uninitialized data
					if (createMemoryBlock(segmentName,
						space.getAddress(segment.getVMaddress()).add(segment.getFileSize()), 0,
						segment.getVMsize() - segment.getFileSize(), segmentName, source,
						segment.isRead(), segment.isWrite(), segment.isExecute(), true) == null) {
						log.appendMsg(String.format("Failed to create block: %s 0x%x 0x%x",
							segment.getSegmentName(), segment.getVMaddress(), segment.getVMsize()));
					}
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

				if (section.getSize() > 0 && (allowZeroAddr || section.getAddress() != 0)) {
					if (createMemoryBlock(section.getSectionName(),
						space.getAddress(section.getAddress()), section.getOffset(),
						section.getSize(), section.getSegmentName(), source, section.isRead(),
						section.isWrite(), section.isExecute(),
						section.getType() == SectionTypes.S_ZEROFILL) == null) {
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
	 * @return The newly created (or split) memory block, or null if it failed to be created. 
	 * @throws Exception If there was a problem creating the new memory block.
	 */
	private MemoryBlock createMemoryBlock(String name, Address start, long dataOffset,
			long dataLength, String comment, String source, boolean r, boolean w, boolean x,
			boolean zeroFill) throws Exception {

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
				return MemoryBlockUtils.createUninitializedBlock(program, false, name, start,
					dataLength, comment, source, r, w, x, log);
			}

			return MemoryBlockUtils.createInitializedBlock(program, false, name, start, fileBytes,
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
	 * @throws Exception if there was a problem fixing up the Program Tree
	 */
	protected void fixupProgramTree() throws Exception {
		ProgramModule rootModule = listing.getDefaultRootModule();
		ListIterator<SegmentCommand> it = machoHeader.getAllSegments().listIterator();
		while (it.hasNext()) {
			int i = it.nextIndex();
			SegmentCommand segment = it.next();

			if (segment.getVMsize() == 0) {
				continue;
			}
			Address segmentStart = space.getAddress(segment.getVMaddress());
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
			if (segmentName.isBlank()) {
				segmentName = "SEGMENT." + i;
			}
			String noSectionsName = segmentName + " <no section>";
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
			ProgramModule segmentModule = rootModule.createModule(segmentName);
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
				Address sectionStart = space.getAddress(section.getAddress());
				Address sectionEnd = sectionStart.add(section.getSize() - 1);
				if (!memory.contains(sectionEnd)) {
					sectionEnd = memory.getBlock(sectionStart).getEnd();
				}
				ProgramFragment sectionFragment = segmentModule.createFragment(
					String.format("%s %s", section.getSegmentName(), section.getSectionName()));
				sectionFragment.move(sectionStart, sectionEnd);
			}
			
			// If the sections fully filled the segment, we can remove the now-empty segment
			if (segmentFragment.isEmpty()) {
				segmentModule.removeChild(segmentFragment.getName());
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

 		for (LoadCommand loadCommand : machoHeader.getLoadCommands(UnsupportedLoadCommand.class)) {
 			monitor.checkCancelled();
 			log.appendMsg(loadCommand.getCommandName());
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
			String name = SymbolUtilities.replaceInvalidChars(export.getName(), true);
			Address exportAddr = baseAddr.add(export.getAddress());
			program.getSymbolTable().addExternalEntryPoint(exportAddr);
			try {
				program.getSymbolTable().createLabel(exportAddr, name, SourceType.IMPORTED);
			}
			catch (Exception e) {
				log.appendMsg("Unable to create symbol: " + e.getMessage());
			}
		}

		return !exports.isEmpty();
 	}

	protected void processSymbolTables(MachHeader header, boolean processExports) throws Exception {
		monitor.setMessage("Processing symbol tables...");
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
					program.getSymbolTable().addExternalEntryPoint(addr);
				}

				String string = symbol.getString();
				if (string.length() == 0) {
					continue;
				}
				string = SymbolUtilities.replaceInvalidChars(string, true);

				if (symbol.isThumbSymbol()) {
					markAsThumb(addr);
				}

				if (program.getSymbolTable().getGlobalSymbol(string, addr) != null) {
					continue;
				}
				try {
					if (!symbol.isExternal() || processExports) {
						program.getSymbolTable().createLabel(addr, string, SourceType.IMPORTED);
						if (symbol.isExternal()) {
							program.getSymbolTable().addExternalEntryPoint(addr);
						}
					}
				}
				catch (Exception e) {
					log.appendMsg("Unable to create symbol: " + e.getMessage());
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

	protected void processLibraries() throws Exception {
		monitor.setMessage("Processing libraries...");

		Options props = program.getOptions(Program.PROGRAM_INFO);
		int libraryIndex = 0;

		for (LoadCommand command : machoHeader.getLoadCommands()) {
			if (monitor.isCancelled()) {
				return;
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
				// For now, strip off the full path and just the use the filename.  We will utilize
				// the full path one day when we started looking in dyld_shared_cache files for
				// libraries.
				int index = libraryPath.lastIndexOf("/");
				String libraryName = index != -1 ? libraryPath.substring(index + 1) : libraryPath;
				if (!libraryName.equals(program.getName())) {
					addLibrary(libraryName);
					props.setString(
						ExternalSymbolResolver.getRequiredLibraryProperty(libraryIndex++),
						libraryName);
				}
			}
		}

		program.getSymbolTable().createExternalLibrary(Library.UNKNOWN, SourceType.IMPORTED);
	}

	protected void processProgramDescription() {
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
				String name = generateValidName(symbol.getString());
				if (name != null && name.length() > 0) {
					program.getSymbolTable().createLabel(start, name, SourceType.IMPORTED);
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
				String name = generateValidName(symbol.getString());
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

	protected void processBindings(boolean doClassic) {
		List<DyldInfoCommand> commands = machoHeader.getLoadCommands(DyldInfoCommand.class);
		for (DyldInfoCommand command : commands) {
			if (command.getBindSize() > 0) {
				BindProcessor processor =
					new BindProcessor(program, machoHeader, provider, command);
				try {
					processor.process(monitor);
				}
				catch (Exception e) {
					log.appendMsg(e.getMessage());
				}
			}
			if (command.getLazyBindSize() > 0) {
				LazyBindProcessor processor =
					new LazyBindProcessor(program, machoHeader, provider, command);
				try {
					processor.process(monitor);
				}
				catch (Exception e) {
					log.appendException(e);
				}
			}
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
	 * intended to reside in memory (like for Mach-O object files}, then this method will create an 
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
		// address and we are done.  Keep track of the lowest file offset of later use.
		for (SegmentCommand segment : segments) {
			if (segment.getFileOffset() == 0 && segment.getFileSize() > 0) {
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

				if (section.getType() == SectionTypes.S_CSTRING_LITERALS) {
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
	 * See crt.c from opensource.apple.com
	 */
	protected void processProgramVars() {
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

	/**
	 * Performs the given relocations.
	 * 
	 * @param relocationMap The relocations to perform, mapped to the addresses they should get
 	 *   performed at.  The relocations must be performed in their supplied order.
 	 * @throws CancelledException if the operation was cancelled.
	 */
	private void performRelocations(LinkedHashMap<RelocationInfo, Address> relocationMap)
 			throws CancelledException {
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
						new long[] { relocationInfo.getValue(),
					relocationInfo.getLength(), relocationInfo.isPcRelocated() ? 1 : 0,
					relocationInfo.isExternal() ? 1 : 0, relocationInfo.isScattered() ? 1 : 0 },
						result.byteLength(),
						relocation != null ? relocation.getTargetDescription() : null);
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
		Address maxAddress = program.getMaxAddress();
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
			int length;
			try {
				listing.createData(address, datatype);
				length = listing.getDataAt(address).getLength();
			}
			catch (Exception e) {
				// don't worry about exceptions
				// may have already been created, by relocation, or chain pointers
				if (!(datatype instanceof Pointer)) {
					log.appendException(e);
				}
				return;
			}
			if (datatype instanceof Pointer) {
				fixupThumbPointers(address);
			}
			address = address.add(length);
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

	private Namespace createNamespace(String namespaceName) {
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

	private String generateValidName(String name) {
		return SymbolUtilities.replaceInvalidChars(name, true);
	}

	/**
	 * create a one-byte function, so that when the code is analyzed,
	 * it will be disassembled, and the function created with the correct body.
	 *
	 * @param name the name of the function
	 * @param address location to create the function
	 */
	void createOneByteFunction(String name, Address address) {
		FunctionManager functionMgr = program.getFunctionManager();
		if (functionMgr.getFunctionAt(address) != null) {
			return;
		}
		try {
			functionMgr.createFunction(name, address, new AddressSet(address), SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			// ignore
		}
		catch (OverlappingFunctionException e) {
			// ignore
		}
	}

	/**
	 * Fixes up any chained fixups.  Relies on the __thread_starts section being present.
	 * 
	 * @return A list of addresses where chained fixups were performed.
	 * @throws Exception if there was a problem reading/writing memory.
	 */
	protected List<Address> processChainedFixups() throws Exception {

		List<Address> fixedAddresses = new ArrayList<>();

		// if has Chained Fixups load command, use it
		List<DyldChainedFixupsCommand> loadCommands =
			machoHeader.getLoadCommands(DyldChainedFixupsCommand.class);
		for (LoadCommand loadCommand : loadCommands) {
			DyldChainedFixupsCommand linkCmd = (DyldChainedFixupsCommand) loadCommand;

			DyldChainedFixupHeader chainHeader = linkCmd.getChainHeader();

			DyldChainedStartsInImage chainedStartsInImage = chainHeader.getChainedStartsInImage();

			DyldChainedStartsInSegment[] chainedStarts = chainedStartsInImage.getChainedStarts();
			for (DyldChainedStartsInSegment chainStart : chainedStarts) {
				fixedAddresses.addAll(processSegmentPointerChain(chainHeader, chainStart));
			}
			log.appendMsg("Fixed up " + fixedAddresses.size() + " chained pointers.");
		}

		// if pointer chains fixed by DyldChainedFixupsCommands, then all finished
		if (loadCommands.size() > 0) {
			return fixedAddresses;
		}

		// if has thread_starts use to fixup chained pointers
		Section threadStarts = machoHeader.getSection(SegmentNames.SEG_TEXT, "__thread_starts");
		if (threadStarts == null) {
			return Collections.emptyList();
		}

		Address threadSectionStart = null;
		Address threadSectionEnd = null;
		threadSectionStart = space.getAddress(threadStarts.getAddress());
		threadSectionEnd = threadSectionStart.add(threadStarts.getSize() - 1);

		monitor.setMessage("Fixing up chained pointers...");

		long nextOffSize = (memory.getInt(threadSectionStart) & 1) * 4 + 4;
		Address chainHead = threadSectionStart.add(4);

		while (chainHead.compareTo(threadSectionEnd) < 0 && !monitor.isCancelled()) {
			int headStartOffset = memory.getInt(chainHead);
			if (headStartOffset == 0xFFFFFFFF || headStartOffset == 0) {
				break;
			}

			Address chainStart = program.getImageBase().add(headStartOffset & 0xffffffffL);
			fixedAddresses.addAll(processPointerChain(chainStart, nextOffSize));
			chainHead = chainHead.add(4);
		}

		log.appendMsg("Fixed up " + fixedAddresses.size() + " chained pointers.");
		return fixedAddresses;
	}

	private List<Address> processSegmentPointerChain(DyldChainedFixupHeader chainHeader,
			DyldChainedStartsInSegment chainStart)
			throws MemoryAccessException, CancelledException {

		List<Address> fixedAddresses = new ArrayList<Address>();
		long fixedAddressCount = 0;

		if (chainStart.getPointerFormat() == 0) {
			return fixedAddresses;
		}

		long dataPageStart = chainStart.getSegmentOffset();
		dataPageStart = dataPageStart + program.getImageBase().getOffset();
		long pageSize = chainStart.getPageSize();
		long pageStartsCount = chainStart.getPageCount();

		long authValueAdd = 0;

		short[] pageStarts = chainStart.getPage_starts();

		short ptrFormatValue = chainStart.getPointerFormat();
		DyldChainType ptrFormat = DyldChainType.lookupChainPtr(ptrFormatValue);

		monitor.setMessage("Fixing " + ptrFormat.getName() + " chained pointers...");

		monitor.setMaximum(pageStartsCount);
		for (int index = 0; index < pageStartsCount; index++) {
			monitor.checkCancelled();

			long page = dataPageStart + (pageSize * index);

			monitor.setProgress(index);

			int pageEntry = pageStarts[index] & 0xffff;
			if (pageEntry == DYLD_CHAINED_PTR_START_NONE) {
				continue;
			}

			List<Address> unchainedLocList = new ArrayList<>(1024);

			long pageOffset = pageEntry; // first entry is byte based

			switch (ptrFormat) {
				case DYLD_CHAINED_PTR_ARM64E:
				case DYLD_CHAINED_PTR_ARM64E_KERNEL:
				case DYLD_CHAINED_PTR_ARM64E_USERLAND:
				case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
					processPointerChain(chainHeader, unchainedLocList, ptrFormat, page, pageOffset,
						authValueAdd);
					break;

				// These might work, but have not been fully tested!
				case DYLD_CHAINED_PTR_64:
				case DYLD_CHAINED_PTR_64_OFFSET:
				case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
				case DYLD_CHAINED_PTR_32:
				case DYLD_CHAINED_PTR_32_CACHE:
				case DYLD_CHAINED_PTR_32_FIRMWARE:
				case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
					processPointerChain(chainHeader, unchainedLocList, ptrFormat, page, pageOffset,
						authValueAdd);
					break;

				case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
				default:
					log.appendMsg(
						"WARNING: Pointer Chain format " + ptrFormat + " not processed yet!");
					break;
			}

			fixedAddressCount += unchainedLocList.size();

			fixedAddresses.addAll(unchainedLocList);
		}

		log.appendMsg(
			"Fixed " + fixedAddressCount + " " + ptrFormat.getName() + " chained pointers.");

		return fixedAddresses;
	}

	/**
	 * Fixes up any chained pointers, starting at the given address.
	 * 
	 * @param chainHeader fixup header chains
	 * @param unchainedLocList list of locations that were unchained
	 * @param pointerFormat format of pointers within this chain
	 * @param page within data pages that has pointers to be unchained
	 * @param nextOff offset within the page that is the chain start
	 * @param auth_value_add value to be added to each chain pointer
	 * 
	 * @throws MemoryAccessException IO problem reading file
	 * @throws CancelledException user cancels
	 */
	private void processPointerChain(DyldChainedFixupHeader chainHeader,
			List<Address> unchainedLocList, DyldChainType pointerFormat, long page, long nextOff,
			long auth_value_add) throws MemoryAccessException, CancelledException {

		long imageBaseOffset = program.getImageBase().getOffset();
		Address chainStart = memory.getProgram().getLanguage().getDefaultSpace().getAddress(page);

		long next = -1;
		boolean start = true;
		while (next != 0) {
			monitor.checkCancelled();

			Address chainLoc = chainStart.add(nextOff);
			final long chainValue = DyldChainedPtr.getChainValue(memory, chainLoc, pointerFormat);
			long newChainValue = chainValue;

			boolean isAuthenticated = DyldChainedPtr.isAuthenticated(pointerFormat, chainValue);
			boolean isBound = DyldChainedPtr.isBound(pointerFormat, chainValue);

			String symName = null;

			if (isAuthenticated && !isBound) {
				long offsetFromSharedCacheBase =
					DyldChainedPtr.getTarget(pointerFormat, chainValue);
				//long diversityData = DyldChainedPtr.getDiversity(pointerFormat, chainValue);
				//boolean hasAddressDiversity =
				//	DyldChainedPtr.hasAddrDiversity(pointerFormat, chainValue);
				//long key = DyldChainedPtr.getKey(pointerFormat, chainValue);
				newChainValue = imageBaseOffset + offsetFromSharedCacheBase + auth_value_add;
			}
			else if (!isAuthenticated && isBound) {
				int chainOrdinal = (int) DyldChainedPtr.getOrdinal(pointerFormat, chainValue);
				long addend = DyldChainedPtr.getAddend(pointerFormat, chainValue);
				DyldChainedImports chainedImports = chainHeader.getChainedImports();
				DyldChainedImport chainedImport = chainedImports.getChainedImport(chainOrdinal);
				//int libOrdinal = chainedImport.getLibOrdinal();
				symName = chainedImport.getName();
				// lookup the symbol, and then add addend
				List<Symbol> globalSymbols = program.getSymbolTable().getGlobalSymbols(symName);
				if (globalSymbols.size() == 1) {
					newChainValue = globalSymbols.get(0).getAddress().getOffset();
				}
				newChainValue += addend;
			}
			else if (isAuthenticated && isBound) {
				int chainOrdinal = (int) DyldChainedPtr.getOrdinal(pointerFormat, chainValue);
				//long addend = DyldChainedPtr.getAddend(pointerFormat, chainValue);
				//long diversityData = DyldChainedPtr.getDiversity(pointerFormat, chainValue);
				//boolean hasAddressDiversity =
				//	DyldChainedPtr.hasAddrDiversity(pointerFormat, chainValue);
				//long key = DyldChainedPtr.getKey(pointerFormat, chainValue);

				DyldChainedImports chainedImports = chainHeader.getChainedImports();
				DyldChainedImport chainedImport = chainedImports.getChainedImport(chainOrdinal);
				symName = chainedImport.getName();

				// lookup the symbol, and then add addend
				List<Symbol> globalSymbols = program.getSymbolTable().getGlobalSymbols(symName);
				if (globalSymbols.size() == 1) {
					newChainValue = globalSymbols.get(0).getAddress().getOffset();
				}
				newChainValue = newChainValue + auth_value_add;
			}
			else {
				newChainValue = DyldChainedPtr.getTarget(pointerFormat, chainValue);
				if (DyldChainedPtr.isRelative(pointerFormat)) {
					newChainValue += imageBaseOffset;
				}
			}

			if (!start || !program.getRelocationTable().hasRelocation(chainLoc)) {
				int byteLength = 0;
				Status status = Status.FAILURE;
				try {
					RelocationResult result =
						DyldChainedPtr.setChainValue(memory, chainLoc, pointerFormat,
							newChainValue);
					status = result.status();
					byteLength = result.byteLength();
				}
				finally {
					if (shouldAddChainedFixupsRelocations) {
						program.getRelocationTable()
								.add(chainLoc, status,
									(start ? 0x8000 : 0x4000) | (isAuthenticated ? 4 : 0) |
										(isBound ? 2 : 0) | 1,
									new long[] { newChainValue }, byteLength, symName);
					}
				}
			}
			// delay creating data until after memory has been changed
			unchainedLocList.add(chainLoc);

			start = false;
			next = DyldChainedPtr.getNext(pointerFormat, chainValue);
			nextOff += next * DyldChainedPtr.getStride(pointerFormat);
		}
	}

	/**
	 * Fixes up any chained pointers, starting at the given address.
	 * 
	 * @param chainStart The starting of address of the pointer chain to fix.
	 * @param nextOffSize The size of the next offset.
	 * @return A list of addresses where pointer fixes were performed.
	 * @throws MemoryAccessException if there was a problem reading/writing memory.
	 */
	private List<Address> processPointerChain(Address chainStart, long nextOffSize)
			throws MemoryAccessException {
		List<Address> fixedAddresses = new ArrayList<>();

		while (!monitor.isCancelled()) {
			long chainValue = memory.getLong(chainStart);

			fixupPointer(chainStart, chainValue);
			fixedAddresses.add(chainStart);

			long nextValueOff = ((chainValue >> 51L) & 0x7ffL) * nextOffSize;
			if (nextValueOff == 0) {
				break;
			}
			chainStart = chainStart.add(nextValueOff);
		}

		return fixedAddresses;
	}

	/**
	 * Fixes up the pointer at the given address.
	 * 
	 * @param pointerAddr The address of the pointer to fix.
	 * @param pointerValue The value at the address of the pointer to fix.
	 * @throws MemoryAccessException if there was a problem reading/writing memory.
	 */
	private void fixupPointer(Address pointerAddr, long pointerValue) throws MemoryAccessException {

		final long BIT63 = (0x1L << 63);
		final long BIT62 = (0x1L << 62);

		// Bad chain value
		if ((pointerValue & BIT62) != 0) {
			// this is a pointer, but is good now
		}

		long fixedPointerValue = 0;
		long fixedPointerType = 0;

		// Pointer checked value
		if ((pointerValue & BIT63) != 0) {
			//long tagType = (pointerValue >> 49L) & 0x3L;
			long pacMod = ((pointerValue >> 32) & 0xffff);
			fixedPointerType = pacMod;
			fixedPointerValue = program.getImageBase().getOffset() + (pointerValue & 0xffffffffL);
		}
		else {
			fixedPointerValue =
				((pointerValue << 13) & 0xff00000000000000L) | (pointerValue & 0x7ffffffffffL);
			if ((pointerValue & 0x40000000000L) != 0) {
				fixedPointerValue |= 0xfffc0000000000L;
			}
		}

		// Add entry to relocation table for the pointer fixup
		byte origBytes[] = new byte[8];
		memory.getBytes(pointerAddr, origBytes);

		boolean success = false;
		try {
			// Fixup the pointer
			memory.setLong(pointerAddr, fixedPointerValue);
			success = true;
		}
		finally {
			Status status = success ? Status.APPLIED : Status.FAILURE;
			program.getRelocationTable()
					.add(pointerAddr, status, (int) fixedPointerType,
						new long[] { fixedPointerValue },
						origBytes, null);
		}
	}

	/**
	 * Markup the given {@link List} of chained fixups by creating pointers at their locations,
	 * if possible
	 * 
	 * @param chainedFixups  The {@link List} of chained fixups to markup
	 * @throws CancelledException if the operation was cancelled
	 */
	protected void markupChainedFixups(List<Address> chainedFixups) throws CancelledException {
		for (Address addr : chainedFixups) {
			monitor.checkCancelled();
			try {
				listing.createData(addr, Pointer64DataType.dataType);
			}
			catch (CodeUnitInsertionException e) {
				// No worries, something presumably more important was there already
			}
		}
	}
}

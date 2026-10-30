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

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.mz.*;
import ghidra.app.util.bin.format.ne.NewExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.database.module.TreeManager;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.*;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing old-style DOS MZ executables
 * 
 * @see <a href="https://wiki.osdev.org/MZ">OSDev.org MZ</a> 
 * @see <a href="https://www.tavi.co.uk/phobos/exeformat.html">Notes on the format of DOS .EXE files</a> 
 * @see <a href="https://thestarman.pcministry.com/asm/debug/Segments.html">Removing the Mystery from SEGMENT : OFFSET Addressing</a> 
 */
public class MzLoader extends AbstractLibrarySupportLoader {
	public final static String MZ_NAME = "Old-style DOS Executable (MZ)";

	private final static String ENTRY_NAME = "entry";
	private final static int INITIAL_SEGMENT_VAL = 0x1000;
	private final static int PARAGRAPH_SIZE = 0x10;
	private final static int FAR_CALL_OPCODE = 0x9a;
	private final static int FAR_RETURN_IMM_OPCODE = 0xca;
	private final static int FAR_RETURN_OPCODE = 0xcb;
	private final static int FAR_JUMP_OPCODE = 0xea;
	private final static byte MOVW_DS_OPCODE = (byte) 0xba;
	private static final long MIN_BYTE_LENGTH = 4;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}
		MzExecutable mz = new MzExecutable(provider);
		OldDOSHeader header = mz.getHeader();
		if (header.isDosSignature() && !isPe(provider) && !isNe(provider)) {
			List<QueryResult> results =
				QueryOpinionService.query(getName(), "" + header.e_magic(), null);
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
	public void load(Program program, ImporterSettings settings)
			throws IOException, CancelledException {

		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();

		FileBytes fileBytes =
			MemoryBlockUtils.createFileBytes(program, settings.provider(), monitor);
		AddressFactory af = program.getAddressFactory();
		if (!(af.getDefaultAddressSpace() instanceof SegmentedAddressSpace)) {
			throw new IOException("Selected Language must have a segmented address space.");
		}

		SegmentedAddressSpace space = (SegmentedAddressSpace) af.getDefaultAddressSpace();
		MzExecutable mz = new MzExecutable(settings.provider());

		try {
			Set<RelocationFixup> relocationFixups = getRelocationFixups(space, mz, log, monitor);

			processMemoryBlocks(program, fileBytes, space, mz, relocationFixups, log, monitor);
			adjustSegmentStarts(program, mz, relocationFixups, monitor);
			processRelocations(program, space, mz, relocationFixups, log, monitor);
			processEntryPoint(program, space, mz, log, monitor);
			processRegisters(program, mz, log, monitor);
			markupHeaders(program, fileBytes, mz, log, monitor); // Do after adjustSegmentStarts()
		}
		catch (CancelledException e) {
			return;
		}
		catch (IOException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	public String getName() {
		return MZ_NAME;
	}

	@Override
	public int getTierPriority() {
		return 60; // we are less priority than PE!  Important for ProgramLoader
	}

	/**
	 * {@return true if the given {@link ByteProvider} contains a PE binary}
	 * 
	 * @param provider The {@link ByteProvider} to check
	 */
	private boolean isPe(ByteProvider provider) {
		try {
			PortableExecutable pe =
				new PortableExecutable(provider, SectionLayout.FILE, false, false);
			return pe.getNTHeader() != null;
		}
		catch (IOException e) {
			return false;
		}
	}

	/**
	 * {@return true if the given {@link ByteProvider} contains an NE binary}
	 * 
	 * @param provider The {@link ByteProvider} to check
	 */
	private boolean isNe(ByteProvider provider) {
		try {
			NewExecutable ne = new NewExecutable(provider, null);
			return ne.getWindowsHeader() != null;
		}
		catch (IOException e) {
			return false;
		}
	}

	/**
	 * Stores a relocation's fixup information
	 * 
	 * @param relocation The original relocation info
	 * @param address The {@link SegmentedAddress} of the relocation
	 * @param fileOffset The file offset of the relocation
	 * @param segment The fixed-up segment after the relocation is applied
	 * @param valid True if the relocation is valid; otherwise, false
	 */
	private record RelocationFixup(MzRelocation relocation, SegmentedAddress address,
			int fileOffset, int segment, boolean valid) {}

	private void markupHeaders(Program program, FileBytes fileBytes, MzExecutable mz,
			MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Marking up headers...");
		OldDOSHeader header = mz.getHeader();
		int blockSize = paragraphsToBytes(Short.toUnsignedInt(header.e_cparhdr()));
		try {
			Address headerSpaceAddr = AddressSpace.OTHER_SPACE.getAddress(0);
			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true,
				"HEADER", headerSpaceAddr, fileBytes, 0, blockSize, "", "", false,
				false, false, log);
			Address addr = headerBlock.getStart();

			// Header
			DataUtilities.createData(program, addr, mz.getHeader().toDataType(), -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			// Relocation Table
			List<MzRelocation> relocations = mz.getRelocations();
			if (!relocations.isEmpty()) {
				DataType relocationType = relocations.get(0).toDataType();
				int len = relocationType.getLength();
				addr = addr.add(Short.toUnsignedInt(header.e_lfarlc()));
				for (int i = 0; i < relocations.size(); i++) {
					monitor.checkCancelled();
					DataUtilities.createData(program, addr.add(i * len), relocationType, -1,
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
			}

		}
		catch (Exception e) {
			log.appendMsg("Failed to markup headers");
		}
	}

	private void processMemoryBlocks(Program program, FileBytes fileBytes,
			SegmentedAddressSpace space, MzExecutable mz, Set<RelocationFixup> relocationFixups,
			MessageLog log, TaskMonitor monitor) throws Exception {
		monitor.setMessage("Processing memory blocks...");

		OldDOSHeader header = mz.getHeader();
		BinaryReader reader = mz.getBinaryReader();

		// Use relocations to discover what segments are in use.
		// We also know about our desired load module segment, so add that too.	
		Set<SegmentedAddress> knownSegments = new TreeSet<>();
		relocationFixups.stream()
				.filter(RelocationFixup::valid)
				.forEach(rf -> knownSegments.add(space.getAddress(rf.segment, 0)));
		knownSegments.add(space.getAddress(INITIAL_SEGMENT_VAL, 0));
		if (header.e_cs() > 0) {
			knownSegments.add(space.getAddress((INITIAL_SEGMENT_VAL + header.e_cs()) & 0xffff, 0));
		}
		// Allocate an initialized memory block for each segment we know about
		int endOffset = pagesToBytes(Short.toUnsignedInt(header.e_cp()) - 1) +
			Short.toUnsignedInt(header.e_cblp());
		if (endOffset > reader.length()) {
			log.appendMsg(
				"File is 0x%x bytes but header reports 0x%x".formatted(reader.length(), endOffset));
			endOffset = (int) reader.length();
		}
		MemoryBlock lastBlock = null;
		List<SegmentedAddress> orderedSegments = new ArrayList<>(knownSegments);
		for (int i = 0; i < orderedSegments.size(); i++) {
			SegmentedAddress segmentAddr = orderedSegments.get(i);

			int segmentFileOffset = addressToFileOffset(
				(segmentAddr.getSegment() - INITIAL_SEGMENT_VAL) & 0xffff, 0, header);
			if (segmentFileOffset < 0) {
				log.appendMsg("Invalid segment start file location: " + segmentFileOffset);
				continue;
			}

			int numBytes = 0;
			if (i + 1 < orderedSegments.size()) {
				SegmentedAddress end = orderedSegments.get(i + 1);
				int nextSegmentFileOffset = addressToFileOffset(
					(end.getSegment() - INITIAL_SEGMENT_VAL) & 0xffff, 0, header);
				numBytes = nextSegmentFileOffset - segmentFileOffset;
			}
			else {
				// last segment length
				numBytes = endOffset - segmentFileOffset;
			}
			if (numBytes <= 0) {
				log.appendMsg("No file data available for defined segment at: " + segmentAddr);
				continue;
			}
			int numUninitBytes = 0;
			if (segmentFileOffset + numBytes > endOffset) {
				int calcNumBytes = numBytes;
				if (segmentFileOffset > endOffset) {
					numBytes = 0;
					numUninitBytes = calcNumBytes;
				}
				else {
					numBytes = endOffset - segmentFileOffset;
					numUninitBytes = calcNumBytes - numBytes;
				}
			}
			if (numBytes > 0) {
				MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false,
					"CODE_" + i, segmentAddr, fileBytes, segmentFileOffset, numBytes, "", "mz",
					true, true, true, log);
				if (block != null) {
					lastBlock = block;
				}
			}
			if (numUninitBytes > 0) {
				MemoryBlock block =
					MemoryBlockUtils.createUninitializedBlock(program, false, "CODE_" + i + "u",
						segmentAddr.add(numBytes), numUninitBytes, "", "mz", true, true, false,
						log);
				if (block != null) {
					lastBlock = block;
				}
			}
		}
		if (endOffset < reader.length()) {
			int extraByteCount = (int) reader.length() - endOffset;
			log.appendMsg(
				String.format("File contains 0x%x extra bytes starting at file offset 0x%x",
					extraByteCount, endOffset));
		}

		// Allocate an uninitialized memory block for extra minimum required data space
		if (lastBlock != null) {
			int extraAllocSize = paragraphsToBytes(Short.toUnsignedInt(header.e_minalloc()));
			if (extraAllocSize > 0) {
				MemoryBlockUtils.createUninitializedBlock(program, false, "DATA",
					lastBlock.getEnd().add(1), extraAllocSize, "", "mz", true, true, false, log);

			}
		}
	}

	/**
	 * Moves bytes at the start of each segment's block that belong to the previous segment to the
	 * previous block. The cut goes after the last FAR RETURN in the block's first paragraph, but
	 * not past the segment's lowest far CALL/JMP target; if that target lies in the paragraph and
	 * no FAR RETURN precedes it, the cut goes at the target.
	 *
	 * @param program The program
	 * @param mz The {@link MzExecutable}
	 * @param relocationFixups The relocation fixups
	 * @param monitor A monitor
	 * @throws Exception If a block could not be split or joined
	 */
	private void adjustSegmentStarts(Program program, MzExecutable mz,
			Set<RelocationFixup> relocationFixups, TaskMonitor monitor) throws Exception {
		monitor.setMessage("Adjusting segments...");

		if (!program.hasExclusiveAccess()) {
			return;
		}

		Map<Integer, Integer> farTargets = getFarTargets(mz, relocationFixups);
		Memory memory = program.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();

		for (int i = 1; i < blocks.length; i++) {
			monitor.checkCancelled();
			MemoryBlock block = blocks[i];
			if (!block.isInitialized() ||
				!(block.getStart() instanceof SegmentedAddress start)) {
				continue;
			}
			int farTarget = farTargets.getOrDefault(start.getSegment(), PARAGRAPH_SIZE);
			int limit = Math.min(farTarget, PARAGRAPH_SIZE);
			int cut = farReturnEnd(block, limit);
			if (cut == 0 && limit < PARAGRAPH_SIZE) {
				cut = limit;
			}
			if (cut == 0 || cut >= block.getSize()) {
				continue;
			}
			// split here and join to previous
			String oldName = block.getName();
			String oldSourceName = block.getSourceName();
			memory.split(block, start.add(cut));
			memory.join(blocks[i - 1], blocks[i]);
			blocks = memory.getBlocks();
			blocks[i].setName(oldName);
			blocks[i].setSourceName(oldSourceName);
		}

		// Recreate the Program Tree since it may now be out of sync
		program.getListing().removeTree(TreeManager.DEFAULT_TREE_NAME);
		program.getListing().createRootModule(TreeManager.DEFAULT_TREE_NAME);
	}

	/**
	 * {@return the lowest far CALL/JMP (ptr16:16) target offset in each relocated segment}
	 *
	 * @param mz The {@link MzExecutable}
	 * @param relocationFixups The relocation fixups
	 */
	private Map<Integer, Integer> getFarTargets(MzExecutable mz,
			Set<RelocationFixup> relocationFixups) {
		Map<Integer, Integer> farTargets = new HashMap<>();
		BinaryReader reader = mz.getBinaryReader();
		int imageStart = paragraphsToBytes(Short.toUnsignedInt(mz.getHeader().e_cparhdr()));
		for (RelocationFixup fixup : relocationFixups) {
			// the opcode (9a/ea), then the 2-byte target offset, precede the relocated segment word
			int opcodeOffset = fixup.fileOffset() - 3;
			if (!fixup.valid() || opcodeOffset < imageStart) {
				continue;
			}
			try {
				int opcode = reader.readUnsignedByte(opcodeOffset);
				if (opcode == FAR_CALL_OPCODE || opcode == FAR_JUMP_OPCODE) {
					farTargets.merge(fixup.segment(), reader.readUnsignedShort(opcodeOffset + 1),
						Math::min);
				}
			}
			catch (IOException e) {
				// not readable, so no evidence
			}
		}
		return farTargets;
	}

	/**
	 * {@return the offset just past the last FAR RETURN (RETF or RETF imm16) in the first
	 * {@code limit} bytes of the block, leaving at least one byte in the block, or 0 if there is
	 * none}
	 *
	 * @param block The block
	 * @param limit How many bytes to scan
	 * @throws MemoryAccessException If the block's bytes cannot be read
	 */
	private int farReturnEnd(MemoryBlock block, int limit) throws MemoryAccessException {
		int end = (int) Math.min(limit, block.getSize() - 1);
		for (int index = end - 1; index >= 0; index--) {
			int length = switch (block.getByte(block.getStart().add(index)) & 0xff) {
				case FAR_RETURN_OPCODE -> 1;
				case FAR_RETURN_IMM_OPCODE -> 3;
				default -> 0;
			};
			if (length != 0 && index + length <= end) {
				return index + length;
			}
		}
		return 0;
	}

	private void processRelocations(Program program, SegmentedAddressSpace space, MzExecutable mz,
			Set<RelocationFixup> relocationFixups, MessageLog log, TaskMonitor monitor)
			throws Exception {
		monitor.setMessage("Processing relocations...");
		Memory memory = program.getMemory();

		for (RelocationFixup relocationFixup : relocationFixups) {
			SegmentedAddress relocationAddress = relocationFixup.address();
			Status status = Status.FAILURE;
			try {
				if (relocationFixup.valid) {
					memory.setShort(relocationAddress, (short) relocationFixup.segment());
					status = Status.APPLIED;
				}
			}
			catch (MemoryAccessException e) {
				log.appendMsg(String.format("Failed to apply relocation: %s (%s)",
					relocationAddress, e.getMessage()));
			}

			// Add to relocation table
			program.getRelocationTable()
					.add(relocationAddress, status, 0,
						new long[] { relocationFixup.relocation.getSegment(),
							relocationFixup.relocation.getOffset(), relocationFixup.segment },
						2, null);
		}
	}

	private void processEntryPoint(Program program, SegmentedAddressSpace space, MzExecutable mz,
			MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Processing entry point...");

		OldDOSHeader header = mz.getHeader();

		int ipValue = Short.toUnsignedInt(header.e_ip());

		Address addr =
			space.getAddress((INITIAL_SEGMENT_VAL + header.e_cs()) & 0xffff, ipValue);
		SymbolTable symbolTable = program.getSymbolTable();

		try {
			symbolTable.createLabel(addr, ENTRY_NAME, SourceType.IMPORTED);
			symbolTable.addExternalEntryPoint(addr);
		}
		catch (InvalidInputException e) {
			log.appendMsg("Failed to process entry point");
		}
	}

	private void processRegisters(Program program, MzExecutable mz, MessageLog log,
			TaskMonitor monitor) {
		monitor.setMessage("Processing registers...");

		Symbol entry = SymbolUtilities.getLabelOrFunctionSymbol(program, ENTRY_NAME,
			err -> log.appendMsg(err));
		if (entry == null) {
			return;
		}

		// TODO: can better do this in an analyzer on the entry point
		//       might work in some cases.
		DataConverter converter = LittleEndianDataConverter.INSTANCE;
		boolean shouldSetDS = false;
		long dsValue = 0;
		try {
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (block.contains(entry.getAddress())) {
					byte instByte = block.getByte(entry.getAddress());
					if (instByte == MOVW_DS_OPCODE) { //is instruction "movw %dx,$0x1234"
						byte[] dsBytes = new byte[2];
						block.getBytes(entry.getAddress().addWrap(1), dsBytes);
						dsValue = converter.getShort(dsBytes);
						shouldSetDS = true;
					}
					break;
				}
			}
		}
		catch (MemoryAccessException e) {
			//unable to set the DS register..
		}

		OldDOSHeader header = mz.getHeader();
		ProgramContext context = program.getProgramContext();
		Register ss = context.getRegister("ss");
		Register sp = context.getRegister("sp");
		Register ds = context.getRegister("ds");
		Register cs = context.getRegister("cs");
		Register cseg = context.getRegister("cseg");

		try {
			context.setValue(sp, entry.getAddress(), entry.getAddress(),
				BigInteger.valueOf(Short.toUnsignedLong(header.e_sp())));
			context.setValue(ss, entry.getAddress(), entry.getAddress(),
				BigInteger.valueOf(
					Integer.toUnsignedLong((header.e_ss() + INITIAL_SEGMENT_VAL) & 0xffff)));

			for (MemoryBlock block : program.getMemory().getBlocks()) {
				Address start = block.getStart();
				Address end = block.getEnd();
				
				if (!(start.getAddressSpace() instanceof SegmentedAddressSpace)) {
					continue;
				}
				
				BigInteger csValue = BigInteger
						.valueOf(Integer.toUnsignedLong(((SegmentedAddress) start).getSegment()));
				
				context.setValue(cs, start, end, csValue);
				if (cseg != null) {
					// a block may run past seg:FFFF, which this CS cannot reach
					int reach = 0x10000 - ((SegmentedAddress) start).getSegmentOffset();
					Address csegEnd = start.add(Math.min(block.getSize(), reach) - 1);
					context.setValue(cseg, start, csegEnd, csValue);
				}
				if (shouldSetDS) {
					context.setValue(ds, start, end, BigInteger.valueOf(dsValue));
				}
			}
		}
		catch (ContextChangeException e) {
			// only a context register write over an instruction throws; cs and ds are
			// plain registers, and the loader has created no instructions for cseg to hit
		}
	}

	/**
	 * Gets a {@link Set} of {@link RelocationFixup relocation fixups}, adjusted to where the image
	 * is loaded into memory
	 * 
	 * @param space The address space
	 * @param mz The {@link MzExecutable}
	 * @param monitor A monitor
	 * @return A {@link Set} of {@link RelocationFixup relocation fixups}, adjusted to where the 
	 *   image is loaded into memory
	 * @throws CancelledException If the action was cancelled
	 */
	private Set<RelocationFixup> getRelocationFixups(SegmentedAddressSpace space,
			MzExecutable mz, MessageLog log, TaskMonitor monitor) throws CancelledException {
		Set<RelocationFixup> fixups = new HashSet<>();

		OldDOSHeader header = mz.getHeader();
		BinaryReader reader = mz.getBinaryReader();

		for (MzRelocation relocation : mz.getRelocations()) {
			monitor.checkCancelled();

			int seg = relocation.getSegment();
			int off = relocation.getOffset();

			int relocationFileOffset = addressToFileOffset(seg, off, header);
			SegmentedAddress relocationAddress =
				space.getAddress((INITIAL_SEGMENT_VAL + seg) & 0xffff, off);

			try {
				int value = Short.toUnsignedInt(reader.readShort(relocationFileOffset));
				int relocatedSegment = (INITIAL_SEGMENT_VAL + value) & 0xffff;
				fixups.add(new RelocationFixup(relocation, relocationAddress, relocationFileOffset,
					relocatedSegment, true));
			}
			catch (AddressOutOfBoundsException | IOException e) {
				fixups.add(new RelocationFixup(relocation, relocationAddress, relocationFileOffset,
					0, false));
				log.appendMsg(String.format("Failed to process relocation: %s (%s)",
					relocationAddress, e.getMessage()));
			}
		}

		return fixups;
	}

	/**
	 * Converts a segmented address to a file offset
	 * 
	 * @param segment The segment
	 * @param offset The offset
	 * @param header The header
	 * @return The segmented addresses converted to a file offset
	 */
	private int addressToFileOffset(int segment, int offset, OldDOSHeader header) {
		return (segment << 4) + offset + paragraphsToBytes(Short.toUnsignedInt(header.e_cparhdr()));
	}

	/**
	 * Converts paragraphs to bytes.  There are 16 bytes in a paragraph.
	 * 
	 * @param paragraphs The number of paragraphs
	 * @return The number of bytes in the given number of paragraphs
	 */
	private int paragraphsToBytes(int paragraphs) {
		return paragraphs << 4;
	}

	/**
	 * Converts pages to bytes.  There are 512 bytes in a page.
	 * 
	 * @param pages The number of pages
	 * @return The number of bytes in the given number of pages
	 */
	private int pagesToBytes(int pages) {
		return pages << 9;
	}
}

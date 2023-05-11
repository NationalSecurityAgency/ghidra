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
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.mz.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
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
	private final static int FAR_RETURN_OPCODE = 0xCB;
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
		if (header.isDosSignature() && !header.hasNewExeHeader() && !header.hasPeHeader()) {
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
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		AddressFactory af = program.getAddressFactory();
		if (!(af.getDefaultAddressSpace() instanceof SegmentedAddressSpace)) {
			throw new IOException("Selected Language must have a segmented address space.");
		}

		SegmentedAddressSpace space = (SegmentedAddressSpace) af.getDefaultAddressSpace();
		MzExecutable mz = new MzExecutable(provider);

		try {
			Set<RelocationFixup> relocationFixups = getRelocationFixups(space, mz, log, monitor);

			markupHeaders(program, fileBytes, mz, log, monitor);
			processMemoryBlocks(program, fileBytes, space, mz, relocationFixups, log, monitor);
			adjustSegmentStarts(program, monitor);
			processRelocations(program, space, mz, relocationFixups, log, monitor);
			processEntryPoint(program, space, mz, log, monitor);
			processRegisters(program, mz, log, monitor);
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
		return 60; // we are less priority than PE!  Important for AutoImporter
	}

	/**
	 * Stores a relocation's fixup information
	 * 
	 * @param relocation The original relocation info
	 * @param address The {@link SegmentedAddress} of the relocation
	 * @param fileOffset The file offset of the relocation
	 * @param segment The fixed-up segment after the relocation is applied
	 */
	private record RelocationFixup(MzRelocation relocation, SegmentedAddress address,
			int fileOffset, int segment) {}

	private void markupHeaders(Program program, FileBytes fileBytes, MzExecutable mz,
			MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Marking up headers...");
		OldDOSHeader header = mz.getHeader();
		int blockSize = paragraphsToBytes(header.e_cparhdr());
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
				addr = addr.add(header.e_lfarlc());
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
		relocationFixups.forEach(rf -> knownSegments.add(space.getAddress(rf.segment, 0)));
		knownSegments.add(space.getAddress(INITIAL_SEGMENT_VAL, 0));

		// Allocate an initialized memory block for each segment we know about
		int endOffset = pagesToBytes(header.e_cp() - 1) + header.e_cblp();
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
				numBytes = endOffset - segmentFileOffset;
				numUninitBytes = calcNumBytes - numBytes;
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
			int extraAllocSize = paragraphsToBytes(header.e_minalloc());
			if (extraAllocSize > 0) {
				MemoryBlockUtils.createUninitializedBlock(program, false, "DATA",
					lastBlock.getEnd().add(1), extraAllocSize, "", "mz", true, true, false, log);

			}
		}
	}

	private void adjustSegmentStarts(Program program, TaskMonitor monitor) throws Exception {
		monitor.setMessage("Adjusting segments...");

		if (!program.hasExclusiveAccess()) {
			return;
		}

		Memory memory = program.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();

		for (int i = 1; i < blocks.length; i++) {
			monitor.checkCancelled();
			MemoryBlock block = blocks[i];
			if (!block.isInitialized()) {
				continue;
			}
			//scan the first 0x10 bytes of this block
			//if a FAR RETURN exists, then move that code
			//to the preceding block...
			int mIndex = 15;
			if (block.getSize() <= 16) {
				mIndex = (int) block.getSize() - 2;
			}
			for (; mIndex >= 0; mIndex--) {
				monitor.checkCancelled();
				Address offAddr = block.getStart().add(mIndex);
				int val = block.getByte(offAddr);
				val &= 0xff;
				if (val == FAR_RETURN_OPCODE) {
					// split here and join to previous
					Address splitAddr = offAddr.add(1);
					String oldName = block.getName();
					memory.split(block, splitAddr);
					memory.join(blocks[i - 1], blocks[i]);
					blocks = memory.getBlocks();
					blocks[i].setName(oldName);
					break;
				}
			}
		}
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
				memory.setShort(relocationAddress, (short) relocationFixup.segment());
				status = Status.APPLIED;
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
				
				BigInteger csValue = BigInteger.valueOf(
						Integer.toUnsignedLong(((SegmentedAddress) start).getSegment()));
				
				context.setValue(cs, start, end, csValue);
				if (shouldSetDS) {
					context.setValue(ds, start, end, BigInteger.valueOf(dsValue));
				}
			}
		}
		catch (ContextChangeException e) {
			// ignore since segment registers should never cause this error
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
					relocatedSegment));
			}
			catch (AddressOutOfBoundsException | IOException e) {
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
		return (short) segment * 16 + offset + paragraphsToBytes(header.e_cparhdr());
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
	 * Converts pages to bytes.  There are 512 bytes in a paragraph.
	 * 
	 * @param pages The number of pages
	 * @return The number of bytes in the given number of pages
	 */
	private int pagesToBytes(int pages) {
		return pages << 9;
	}
}

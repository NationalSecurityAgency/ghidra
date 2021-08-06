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

import generic.continues.ContinuesFactory;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.mz.OldStyleExecutable;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing Microsoft DOS MZ files.
 */
public class MzLoader extends AbstractLibrarySupportLoader {
	public final static String MZ_NAME = "Old-style DOS Executable (MZ)";

	private final static String ENTRY_NAME = "entry";
	private final static int INITIAL_SEGMENT_VAL = 0x1000;
	private final static int FAR_RETURN_OPCODE = 0xCB;
	private final static byte MOVW_DS_OPCODE = (byte) 0xba;
	private static final long MIN_BYTE_LENGTH = 4;

	private DataConverter converter = LittleEndianDataConverter.INSTANCE;

	@Override
	public int getTierPriority() {
		return 60; // we are less priority than PE!  Important for AutoImporter
	}

	public MzLoader() {
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}
		OldStyleExecutable ose = new OldStyleExecutable(RethrowContinuesFactory.INSTANCE, provider);
		DOSHeader dos = ose.getDOSHeader();
		if (dos.isDosSignature() && !dos.hasNewExeHeader() && !dos.hasPeHeader()) {
			List<QueryResult> results =
				QueryOpinionService.query(getName(), "" + dos.e_magic(), null);
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

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(prog, provider, monitor);
		AddressFactory af = prog.getAddressFactory();
		if (!(af.getDefaultAddressSpace() instanceof SegmentedAddressSpace)) {
			throw new IOException("Selected Language must have a segmented address space.");
		}

		SegmentedAddressSpace space = (SegmentedAddressSpace) af.getDefaultAddressSpace();
		SymbolTable symbolTable = prog.getSymbolTable();
		ProgramContext context = prog.getProgramContext();
		Memory memory = prog.getMemory();

		ContinuesFactory factory = MessageLogContinuesFactory.create(log);
		OldStyleExecutable ose = new OldStyleExecutable(factory, provider);
		DOSHeader dos = ose.getDOSHeader();
		FactoryBundledWithBinaryReader reader = ose.getBinaryReader();

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing segments...");
		processSegments(prog, fileBytes, space, reader, dos, log, monitor);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Adjusting segments...");
		adjustSegmentStarts(prog);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing relocations...");
		doRelocations(prog, reader, dos);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing symbols...");
		createSymbols(space, symbolTable, dos);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Setting registers...");

		Symbol entrySymbol = SymbolUtilities.getLabelOrFunctionSymbol(prog, ENTRY_NAME,
			err -> log.appendMsg("MZ", err));
		setRegisters(context, entrySymbol, memory.getBlocks(), dos);

	}

	private void setRegisters(ProgramContext context, Symbol entry, MemoryBlock[] blocks,
			DOSHeader dos) {
		if (entry == null) {
			return;
		}
		boolean shouldSetDS = false;
		long dsValue = 0;
		try {
			for (MemoryBlock block : blocks) {
				if (block.contains(entry.getAddress())) {
					byte instByte = block.getByte(entry.getAddress());
					if (instByte == MOVW_DS_OPCODE) {//is instruction "movw %dx,$0x1234"
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

		Register ss = context.getRegister("ss");
		Register sp = context.getRegister("sp");
		Register ds = context.getRegister("ds");
		Register cs = context.getRegister("cs");

		try {
			context.setValue(sp, entry.getAddress(), entry.getAddress(),
				BigInteger.valueOf(Conv.shortToLong(dos.e_sp())));
			context.setValue(ss, entry.getAddress(), entry.getAddress(),
				BigInteger.valueOf(Conv.shortToLong(dos.e_ss())));

			BigInteger csValue = BigInteger.valueOf(
				Conv.intToLong(((SegmentedAddress) entry.getAddress()).getSegment()));

			for (MemoryBlock block : blocks) {
				Address start = block.getStart();
				Address end = block.getEnd();
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

	private void adjustSegmentStarts(Program prog) {
		Memory mem = prog.getMemory();

		if (!prog.hasExclusiveAccess()) {
			return;
		}

		MemoryBlock[] blocks = mem.getBlocks();
		for (int i = 1; i < blocks.length; i++) {
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
				try {
					Address offAddr = block.getStart().add(mIndex);
					int val = block.getByte(offAddr);
					val &= 0xff;
					if (val == FAR_RETURN_OPCODE) {
						// split here and join to previous
						Address splitAddr = offAddr.add(1);
						String oldName = block.getName();
						mem.split(block, splitAddr);
						mem.join(blocks[i - 1], blocks[i]);
						blocks = mem.getBlocks();
						blocks[i].setName(oldName);
						break;
					}
				}
				catch (LockException e) {
					// TODO: ignore?
				}
				catch (MemoryBlockException e) {
					// TODO: ignore?
				}
				catch (AddressOutOfBoundsException e) {
					// TODO: ignore?
				}
				catch (MemoryAccessException e) {
					// TODO: ignore?
				}
				catch (NotFoundException e) {
					// TODO: ignore?
				}
			}
		}
	}

	private void processSegments(Program program, FileBytes fileBytes, SegmentedAddressSpace space,
			FactoryBundledWithBinaryReader reader, DOSHeader dos, MessageLog log,
			TaskMonitor monitor) {
		try {
			int relocationTableOffset = Conv.shortToInt(dos.e_lfarlc());
			int csStart = INITIAL_SEGMENT_VAL;
			int dataStart = dos.e_cparhdr() << 4;

			HashMap<Address, Address> segMap = new HashMap<Address, Address>();
			SegmentedAddress codeAddress =
				space.getAddress(Conv.shortToInt(dos.e_cs()) + csStart, 0);
			segMap.put(codeAddress, codeAddress);
			codeAddress = space.getAddress(csStart, 0);
			segMap.put(codeAddress, codeAddress);			// This is there data starts loading
			int numRelocationEntries = dos.e_crlc();
			reader.setPointerIndex(relocationTableOffset);
			for (int i = 0; i < numRelocationEntries; i++) {
				int off = Conv.shortToInt(reader.readNextShort());
				int seg = Conv.shortToInt(reader.readNextShort());

				// compute the new segment referenced at the location
				SegmentedAddress segStartAddr = space.getAddress(seg + csStart, 0);
				segMap.put(segStartAddr, segStartAddr);

				int location = (seg << 4) + off;
				int locOffset = location + dataStart;

				int value = Conv.shortToInt(reader.readShort(locOffset));
				int fixupAddrSeg = (value + csStart) & Conv.SHORT_MASK;
				SegmentedAddress fixupAddr = space.getAddress(fixupAddrSeg, 0);
				segMap.put(fixupAddr, fixupAddr);
			}

			int exeBlockCount = dos.e_cp();
			int exeEndOffset = exeBlockCount * 512;
			int bytesUsedInLastBlock = dos.e_cblp();
			if (bytesUsedInLastBlock != 0) {
				exeEndOffset -= (512 - bytesUsedInLastBlock);
			}

			ArrayList<Address> segStartList = new ArrayList<Address>(segMap.values());
			int csStartEffective = csStart << 4;
			Collections.sort(segStartList);
			for (int i = 0; i < segStartList.size(); i++) {
				SegmentedAddress start = (SegmentedAddress) segStartList.get(i);

				int readLoc = ((start.getSegment() << 4) - csStartEffective) + dataStart;
				if (readLoc < 0) {
					Msg.error(this, "Invalid read location " + readLoc);
					continue;
				}

				int numBytes = 0;
				if ((i + 1) < segStartList.size()) {
					SegmentedAddress end = (SegmentedAddress) segStartList.get(i + 1);
					int nextLoc = ((end.getSegment() << 4) - csStartEffective) + dataStart;
					numBytes = nextLoc - readLoc;
				}
				else {
					// last segment length
					numBytes = exeEndOffset - readLoc;
				}
				if (numBytes <= 0) {
					log.appendMsg("No EXE file data available for defined segment at: " + start);
					continue;
				}
				int numUninitBytes = 0;
				if ((readLoc + numBytes) > exeEndOffset) {
					int calcNumBytes = numBytes;
					numBytes = exeEndOffset - readLoc;
					numUninitBytes = calcNumBytes - numBytes;
				}
				if (numBytes > 0) {
					MemoryBlockUtils.createInitializedBlock(program, false, "Seg_" + i, start,
						fileBytes, readLoc, numBytes, "", "mz", true, true, true, log);
				}
				if (numUninitBytes > 0) {
					MemoryBlockUtils.createUninitializedBlock(program, false, "Seg_" + i + "u",
						start.add(numBytes), numUninitBytes, "", "mz", true, true, false, log);
				}
			}

			if (exeEndOffset < reader.length()) {
				int extraByteCount = (int) reader.length() - exeEndOffset;
				log.appendMsg("File contains 0x" + Integer.toHexString(extraByteCount) +
					" extra bytes starting at file offset 0x" + Integer.toHexString(exeEndOffset));
			}

//			// create the stack segment
//			SegmentedAddress stackStart = space.getAddress((dos.e_ss() + csStart), 0);
//			mbu.createUninitializedBlock(false, "Stack", stackStart, dos.e_sp(), "", "", true, true, false);

		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		catch (AddressOverflowException e) {
			throw new RuntimeException(e);
		}
	}

	private void doRelocations(Program prog, FactoryBundledWithBinaryReader reader, DOSHeader dos) {
		try {
			Memory mem = prog.getMemory();
			SegmentedAddressSpace space =
				(SegmentedAddressSpace) prog.getAddressFactory().getDefaultAddressSpace();

			int relocationTableOffset = Conv.shortToInt(dos.e_lfarlc());
			int csStart = INITIAL_SEGMENT_VAL;
			int dataStart = dos.e_cparhdr() << 4;

			int numRelocationEntries = dos.e_crlc();
			reader.setPointerIndex(relocationTableOffset);
			for (int i = 0; i < numRelocationEntries; i++) {
				int off = Conv.shortToInt(reader.readNextShort());
				int seg = Conv.shortToInt(reader.readNextShort());

				//SegmentedAddress segStartAddr = space.getAddress(seg + csStart, 0);

				int location = (seg << 4) + off;
				int locOffset = location + dataStart;

				// compute the new segment referenced at the location
				SegmentedAddress fixupAddr = space.getAddress(seg + csStart, off);
				int value = Conv.shortToInt(reader.readShort(locOffset));
				int fixupAddrSeg = (value + csStart) & Conv.SHORT_MASK;
				mem.setShort(fixupAddr, (short) fixupAddrSeg);

				// Add to relocation table
				prog.getRelocationTable()
						.add(fixupAddr, 0, new long[] { off, seg }, converter.getBytes(value),
							null);
			}
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		catch (MemoryAccessException e) {
			throw new RuntimeException(e);
		}
	}

	private void createSymbols(SegmentedAddressSpace space, SymbolTable symbolTable,
			DOSHeader dos) {
		int ipValue = Conv.shortToInt(dos.e_ip());
		int codeSegment = Conv.shortToInt(dos.e_cs()) + INITIAL_SEGMENT_VAL;

		if (codeSegment > Conv.SHORT_MASK) {
			System.out.println("Invalid entry point location: " + Integer.toHexString(codeSegment) +
				":" + Integer.toHexString(ipValue));
			return;
		}

		Address addr = space.getAddress(codeSegment, ipValue);

		try {
			symbolTable.createLabel(addr, ENTRY_NAME, SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			// Just skip if we can't create
		}

		symbolTable.addExternalEntryPoint(addr);
	}

	@Override
	public String getName() {
		return MZ_NAME;
	}
}

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
package ghidra.program.util;

import java.util.*;

import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import utility.function.TerminatingConsumer; 

/**
 * <CODE>ProgramMemoryUtil</CODE> contains some static methods for 
 * checking Memory block data.
 */

public class ProgramMemoryUtil {

//    /**
//     * Gets the ProgramMemoryBlocks from a program that contain addresses 
//     * in the address set.
//     * @param p the program
//     * @param as the set of addresses whose blocks are wanted.
//     */
//    public static MemoryBlock[] getBlocksContaining(Program p, AddressSet as) {
//        MemoryBlock[] memBlocks = getMemBlocks(p);
//        AddressRange[] blockRanges = memBlocksToRanges(memBlocks);
//        AddressRange[] addrRanges = getRangesAsArray(as);
//        // The following assumes the address ranges are in ascending order and 
//        // that the block ranges are also in ascending order.
//        ArrayList list = new ArrayList(blockRanges.length);
//        int addrRef = 0;
//        int blockRef = 0;
//        while ((blockRef < blockRanges.length) && (addrRef < addrRanges.length)) {
//            Address addrMin = addrRanges[addrRef].getMinAddress();
//            Address addrMax = addrRanges[addrRef].getMaxAddress();
//            Address blockMin = blockRanges[blockRef].getMinAddress();
//            Address blockMax = blockRanges[blockRef].getMaxAddress();
//            int addrMinBlockMin = addrMin.compareTo(blockMin);
//            int addrMaxBlockMin = addrMax.compareTo(blockMin);
//            int addrMinBlockMax = addrMin.compareTo(blockMax);
//            int addrMaxBlockMax = addrMax.compareTo(blockMax);
//            if ((addrMinBlockMin < 0) && (addrMaxBlockMin < 0)) {
//                // NOT IN THE BLOCK (Before the block)
//                addrRef++;
//            }
//            else if (((addrMinBlockMin <= 0) && (addrMaxBlockMin >= 0))
//                  || ((addrMinBlockMin >= 0) && (addrMinBlockMax <= 0))) {
//                // IS IN THE BLOCK (Overlaps the block)
//                list.add(memBlocks[blockRef]);
//                blockRef++;
//            }
//            else if ((addrMinBlockMax > 0) && (addrMaxBlockMax > 0)) {
//                // NOT IN THE BLOCK (After the block)
//                blockRef++;
//            }
//        }
//        return (MemoryBlock[])list.toArray(new MemoryBlock[list.size()]);
//    }

//    /** Gets the address ranges thaqt make up the address set.
//     * @param as the address set
//     * @return the ranges.
//     */
//    public static AddressRange[] getRangesAsArray(AddressSet as) {
//        AddressRange[] addrRanges = new AddressRange[as.getNumAddressRanges()];
//        AddressRangeIterator iter = as.getAddressRanges();
//        for (int i=0; iter.hasNext(); i++) {
//            addrRanges[i] = (AddressRange)iter.next();
//        }
//        return addrRanges;
//    }

	/**
	 * Copies the bytes to one program from another for the specified address 
	 * range.
	 * @param toProgram program that the bytes are copied to.
	 * @param fromProgram program the bytes are copied from.
	 * @param minAddr the minimum address of the range to be copied.
	 * This address should be derived from the toProgram.
	 * @param maxAddr the maximum address of the range to be copied.
	 * This address should be derived from the toProgram.
	 * 
	 * @throws MemoryAccessException if bytes can't be copied.
	 */
	public static void copyBytesInRanges(Program toProgram, Program fromProgram, Address minAddr,
			Address maxAddr) throws MemoryAccessException {
		Memory toMem = toProgram.getMemory();
		Memory fromMem = fromProgram.getMemory();
		AddressRange range = new AddressRangeImpl(minAddr, maxAddr);
		copyByteRange(toMem, fromMem, range);
	}

	/**
	 * Copies the bytes to one program from another for the specified set of
	 * address ranges.
	 * @param toProgram program that the bytes are copied to.
	 * @param fromProgram program the bytes are copied from.
	 * @param addrSet the set of address ranges to be copied.
	 * The addresses in this set are derived from the "to program".
	 * 
	 * @throws MemoryAccessException if bytes can't be copied.
	 * @throws CancelledException if user cancels copy bytes via the monitor.
	 */
	public static void copyBytesInRanges(Program toProgram, Program fromProgram,
			AddressSetView addrSet, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		Memory toMem = toProgram.getMemory();
		Memory fromMem = fromProgram.getMemory();
		// Copy each range.
		AddressRangeIterator iter = addrSet.getAddressRanges();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			AddressRange range = iter.next();
			copyByteRange(toMem, fromMem, range);
		}
	}

	/**
	 * Copies the bytes to one program memory from another for the specified 
	 * address range.
	 * @param toMem program memory that the bytes are copied to.
	 * @param fromMem program memory the bytes are copied from.
	 * @param range the address range to be copied.
	 * The addresses in this range are derived from the program associated with the "to memory".
	 * 
	 * @throws MemoryAccessException if bytes can't be copied.
	 */
	private static void copyByteRange(Memory toMem, Memory fromMem, AddressRange range)
			throws MemoryAccessException {
		// Copy the bytes for this range
		int length = 0;
		Address writeAddress = range.getMinAddress();
		for (long len = range.getLength(); len > 0; len -= length) {
			length = (int) Math.min(len, Integer.MAX_VALUE);
			byte[] bytes = new byte[length];
			fromMem.getBytes(writeAddress, bytes);
			toMem.setBytes(writeAddress, bytes);
			if (len > length) {
				writeAddress = writeAddress.add(length);
			}
		}
	}

	/** Gets the program memory blocks of the indicated type for the 
	 * specified program.
	 * @param program the program whose memory blocks we want.
	 * @param withBytes if true include blocks that have their own bytes. If false, include only
	 * blocks that don't have their own bytes (this includes bit and byte mapped blocks)
	 * @return an array of program memory blocks
	 */
	public static MemoryBlock[] getMemBlocks(Program program, boolean withBytes) {
		Memory mem = program.getMemory();
		MemoryBlock[] blocks = mem.getBlocks();
		MemoryBlock[] tmpBlocks = new MemoryBlock[blocks.length];
		int j = 0;
		for (MemoryBlock block : blocks) {
			if ((block.isInitialized() && withBytes) || (!block.isInitialized() && !withBytes)) {
				tmpBlocks[j++] = block;
			}
		}
		MemoryBlock[] typeBlocks = new MemoryBlock[j];
		System.arraycopy(tmpBlocks, 0, typeBlocks, 0, j);
		return typeBlocks;
	}

	/** 
	 * Gets the address set for the specified program.
	 * @param program the program whose address set we want.
	 * @return the address set
	 */
	public static AddressSetView getAddressSet(Program program) {
		MemoryBlock[] memBlocks = program.getMemory().getBlocks();
		AddressSet addrSet = new AddressSet();
		for (MemoryBlock block : memBlocks) {
			addrSet.add(block.getStart(), block.getEnd());
		}
		return addrSet;
	}

	/** 
	 * Gets a new address set indicating all addresses of the indicated 
	 * memory type in the specified program.
	 * @param program the program whose address set we want.
	 * @param blocksWithBytes if true, include memory blocks that have their own bytes.
	 * @return the memory's address set of the indicated type.
	 */
	public static AddressSet getAddressSet(Program program, boolean blocksWithBytes) {
		MemoryBlock[] memBlocks = ProgramMemoryUtil.getMemBlocks(program, blocksWithBytes);
		AddressSet addrSet = new AddressSet();
		for (MemoryBlock block : memBlocks) {
			addrSet.add(block.getStart(), block.getEnd());
		}
		return addrSet;
	}

	/**
	 * Gets an address set with the overlay addresses that are in the specified program.
	 * @param program the program
	 * @return the overlay addresses within the specified program.
	 */
	public static AddressSet getOverlayAddresses(Program program) {
		AddressSet addrSet = new AddressSet();
		MemoryBlock[] memBlocks = program.getMemory().getBlocks();
		for (MemoryBlock memoryBlock : memBlocks) {
			if (memoryBlock.isOverlay()) {
				AddressRange addressRange =
					new AddressRangeImpl(memoryBlock.getStart(), memoryBlock.getEnd());
				addrSet.add(addressRange);
			}
		}
		return addrSet;
	}

	/**
	 * Checks a programs memory for direct references to the addresses indicated in the toAddressSet.
	 * Direct references are only found at addresses that match the indicated alignment. Each
	 * direct reference is added to the directReferenceList as a from/to address pair.
	 * 
	 * @param program the program whose memory is to be checked.
	 * @param alignment direct references are to only be found at the indicated alignment in memory.
	 * @param toAddress address that we are interested in finding references to.
	 * @param toAddressSet address set indicating the addresses that we are interested in 
	 * 		  finding directly referred to in memory. 
	 * 		  Null if only interested in finding references to the toAddress.
	 * @param directReferenceList the list to be populated with possible direct references
	 * @param monitor a task monitor for progress or to allow cancelling.
	 * @throws CancelledException if the user cancels via the monitor.
	 */
	public static void loadDirectReferenceList(Program program, int alignment, Address toAddress,
			AddressSetView toAddressSet, List<ReferenceAddressPair> directReferenceList,
			TaskMonitor monitor) throws CancelledException {
		Accumulator<ReferenceAddressPair> accumulator = new ListAccumulator<>();
		loadDirectReferenceList(program, alignment, toAddress, toAddressSet, accumulator, monitor);
		directReferenceList.addAll(accumulator.get());
	}

	/**
	 * Checks a programs memory for direct references to the addresses indicated in the toAddressSet.
	 * Direct references are only found at addresses that match the indicated alignment. Each
	 * direct reference is added to the directReferenceList as a from/to address pair.
	 * 
	 * @param program the program whose memory is to be checked.
	 * @param alignment direct references are to only be found at the indicated alignment in memory.
	 * @param toAddress address that we are interested in finding references to.
	 * @param toAddressSet address set indicating the addresses that we are interested in 
	 * 		  finding directly referred to in memory. 
	 * 		  Null if only interested in finding references to the toAddress.
	 * @param accumulator the datastructure to be populated with possible direct references
	 * @param monitor a task monitor for progress or to allow cancelling.
	 * @throws CancelledException if the user cancels via the monitor.
	 */
	public static void loadDirectReferenceList(Program program, int alignment, Address toAddress,
			AddressSetView toAddressSet, Accumulator<ReferenceAddressPair> accumulator,
			TaskMonitor monitor) throws CancelledException {

		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}

		Memory memory = program.getMemory();
		boolean isBigEndian = memory.isBigEndian();
		int unitSize = toAddress.getAddressSpace().getAddressableUnitSize(); //number of bytes per addressable unit
		int addrSize = toAddress.getSize();
		short currentSegment = 0;

		if (toAddressSet == null || toAddressSet.getNumAddresses() == 1) {
			Set<Address> refAddrs = findDirectReferences(program, alignment, toAddress, monitor);
			Iterator<Address> refAddrIter = refAddrs.iterator();
			while (refAddrIter.hasNext() && !monitor.isCancelled()) {
				accumulator.add(new ReferenceAddressPair(refAddrIter.next(), toAddress));
			}
			return;
		}

		// Just looking for the offset into the segment now, not the whole segment/offset pair
		if (toAddress instanceof SegmentedAddress) {
			SegmentedAddress segAddr = (SegmentedAddress) toAddress;
			currentSegment = (short) segAddr.getSegment();
		}

		// iterate over addresses in program
		AddressIterator addrIt = memory.getLoadedAndInitializedAddressSet().getAddresses(true);
		monitor.initialize(memory.getNumAddresses());
		int count = 0;
		while (addrIt.hasNext()) {
			monitor.checkCanceled();
			Address a = addrIt.next();
			++count;
			monitor.setProgress(count);

			if ((a.getOffset() % alignment) != 0) {
				continue;
			}

			long addrLong = 0;
			long addrLongShifted = 0;
			try {
				if (toAddress instanceof SegmentedAddress) {
					short offsetShort = memory.getShort(a);
					offsetShort &= offsetShort & 0xffff;
					// this is checking to see if the ref is in the same segment as the toAddr - not sure this is needed anymore
					// SegmentedAddress sega = ((SegmentedAddress) a);
					// short shortSega = (short) (sega.getSegment());
					// shortSega &= shortSega & 0xffff;
					//	if (offsetShort == shortCurrentOffset) {
					//*** commenting this out is making it find the instances of 46 01's not the 0a 00's - closer though
					// check for the case where the reference includes both the segment and offset
					// and the case where the reference includes only the offset but the address being checked
					// is in the same segment as the current address
					//if ((segmentShort == currentSegment) || (shortSega == currentSegment)) {
					//	addrLong = longCurrentAddress; // this is only so that the check below works
					//}
					addrLong = offsetShort;
					//	}
				}
				else if (addrSize == 16) {
					short addrShort = memory.getShort(a);
					addrLong = addrShort & 0xffffL; // multiply by wordsize because 
					// address offsets are at the byte level,
					// not the addressable word level.
				}
				else if (addrSize == 32) {
					int addrInt = memory.getInt(a);
					addrLong = addrInt & 0xffffffffL;
				}
				else if (addrSize == 64) {
					addrLong = memory.getLong(a);
				}
				else {
					// handle any addrSize the hard way
					byte dest[] = new byte[addrSize / 8];
					int num = memory.getBytes(a, dest);
					if (num != dest.length) {
						continue; // insufficient bytes
					}
					addrLong = 0;
					for (int i = 0; i < dest.length; i++) {
						int destIndex = isBigEndian ? i : (dest.length - i - 1);
						addrLong = (addrLong << 8) | (dest[destIndex] & 0xff);
					}
				}

				Address addr;
				if (toAddress instanceof SegmentedAddress) {
					SegmentedAddressSpace space =
						(SegmentedAddressSpace) toAddress.getAddressSpace();
					addr = space.getAddress(currentSegment, (int) addrLong);
				}
				else {
					addr = toAddress.getNewAddress(addrLong * unitSize);
				}

				Address addrShifted = null;
				int addressShiftAmount =
					program.getDataTypeManager().getDataOrganization().getPointerShift();
				if (addressShiftAmount != 0) {
					// look for addresses that are shifted for those processors who
					// store shifted pointers
					addrLongShifted = addrLong << addressShiftAmount;
					try {
						addrShifted = toAddress.getNewAddress(addrLongShifted * unitSize);
					}
					catch (AddressOutOfBoundsException e) {
						// ignore for now; the null check happens below
					}
				}

				// TODO: This is flawed since the wrong unitSize may have been used to create addr
				//       Each address-space may have a different unitSize - it's a little weird
				//       to have both a toAddress and a toAddressSet specified where toAddress is required
				if (toAddressSet.contains(addr)) {
					accumulator.add(new ReferenceAddressPair(a, addr));
				}
				if (addrShifted != null && toAddressSet.contains(addrShifted)) {
					accumulator.add(new ReferenceAddressPair(a, addrShifted));
				}
			}
			catch (MemoryAccessException e) {
				// ignore (tsk, tsk)
			}
			catch (AddressOutOfBoundsException e) {
				// ignore (tsk, tsk)
			}
		}
	}

	/**
	 * Checks a programs memory for direct references to the CodeUnit indicated.
	 * Direct references are only found at addresses that match the indicated alignment. 
	 * @param program the program whose memory is to be checked.
	 * @param alignment direct references are to only be found at the indicated alignment in memory.
	 * @param codeUnit the code unit to to search for references to.
	 * @param monitor a task monitor for progress or to allow canceling.
	 * @return list of addresses referring directly to the toAddress.
	 */
	public static List<Address> findDirectReferencesCodeUnit(Program program, int alignment,
			CodeUnit codeUnit, TaskMonitor monitor) {

		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}

		AddressSet toAddressSet =
			new AddressSet((codeUnit.getMinAddress()), codeUnit.getMaxAddress());

		List<ReferenceAddressPair> directReferenceList = new ArrayList<>();
		List<Address> results = new ArrayList<>();

		try {
			ProgramMemoryUtil.loadDirectReferenceList(program, alignment,
				toAddressSet.getMinAddress(), toAddressSet, directReferenceList, monitor);
		}
		catch (CancelledException e) {
			return Collections.emptyList();
		}

		for (ReferenceAddressPair rap : directReferenceList) {
			if (monitor.isCancelled()) {
				return null;
			}
			Address fromAddr = rap.getSource();
			if (!results.contains(fromAddr)) {
				results.add(fromAddr);
			}
		}

		return results;
	}

	/**
	 * Checks a programs memory for direct references to the address indicated.
	 * Direct references are only found at addresses that match the indicated alignment. 
	 * 
	 * @param program the program whose memory is to be checked.
	 * @param alignment direct references are to only be found at the indicated alignment in memory.
	 * @param toAddress address that we are interested in finding references to.
	 * @param monitor a task monitor for progress or to allow canceling.
	 * @return list of addresses referring directly to the toAddress
	 * 
	 * @throws CancelledException if the user cancels via the monitor.
	 */
	public static Set<Address> findDirectReferences(Program program, int alignment,
			Address toAddress, TaskMonitor monitor) throws CancelledException {

		return findDirectReferences(program, (List<MemoryBlock>) null, alignment, toAddress,
			monitor);
	}

	/**
	 * Checks a programs memory for direct references to the address indicated within the 
	 * listed memory blocks. If null is passed for the list of memory blocks then all of the
	 * program's memory blocks will be checked.<br>
	 * Direct references are only found at addresses that match the indicated alignment. 
	 * 
	 * @param program the program whose memory is to be checked.
	 * @param blocks the only memory blocks to be checked. A null value indicates all memory 
	 * blocks should be checked.
	 * @param alignment direct references are to only be found at the indicated alignment in memory.
	 * @param toAddress address that we are interested in finding references to.
	 * @param monitor a task monitor for progress or to allow canceling.
	 * @return list of addresses referring directly to the toAddress
	 * 
	 * @throws CancelledException if the user cancels via the monitor.
	 */
	public static Set<Address> findDirectReferences(Program program, List<MemoryBlock> blocks,
			int alignment, Address toAddress, TaskMonitor monitor) throws CancelledException {

		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}

		byte[] addressBytes = getDirectAddressBytes(program, toAddress);

		byte[] shiftedAddressBytes = getShiftedDirectAddressBytes(program, toAddress);

		Memory memory = program.getMemory();
		Set<Address> dirRefsAddrs = new TreeSet<>();
		findBytePattern(memory, blocks, addressBytes, alignment, dirRefsAddrs, monitor);

		if (shiftedAddressBytes != null) { // assume shifted address not supported with segmented memory
			findBytePattern(memory, blocks, shiftedAddressBytes, alignment, dirRefsAddrs, monitor);
		}

		return dirRefsAddrs;
	}

	/**
	 * Get a representation of an address as it would appear in bytes in memory.
	 * 
	 * @param program program
	 * @param toAddress target address
	 * @return byte representation of toAddress
	 */
	public static byte[] getDirectAddressBytes(Program program, Address toAddress) {

		Memory memory = program.getMemory();
		boolean isBigEndian = memory.isBigEndian();

		int addrSize = toAddress.getSize();

		DataConverter dataConverter = DataConverter.getInstance(memory.isBigEndian());
		byte[] addressBytes = new byte[addrSize / 8];

		if (toAddress instanceof SegmentedAddress) {
			// Only search for offset (exclude segment)
			addressBytes = new byte[2];
			SegmentedAddress segAddr = (SegmentedAddress) toAddress;
			short addrShort = (short) segAddr.getSegmentOffset();
			dataConverter.getBytes(addrShort, addressBytes);
		}
		else if (addrSize == 64) {
			long addrLong = toAddress.getAddressableWordOffset();
			dataConverter.getBytes(addrLong, addressBytes);
		}
		else if (addrSize == 32) {
			int addrInt = (int) toAddress.getAddressableWordOffset();
			dataConverter.getBytes(addrInt, addressBytes);
		}
		else if (addrSize == 16) {
			short addrShort = (short) toAddress.getAddressableWordOffset();
			dataConverter.getBytes(addrShort, addressBytes);
		}
		else {
			// Handle any addrSize the hard way
			byte[] tempBytes = new byte[8];
			long addrLong = toAddress.getAddressableWordOffset();
			dataConverter.getBytes(addrLong, tempBytes);
			System.arraycopy(tempBytes, isBigEndian ? (tempBytes.length - addressBytes.length) : 0,
				addressBytes, 0, addressBytes.length);
		}

		return addressBytes;
	}

	/**
	 * returns shifted address bytes if they are different than un-shifted
	 * 
	 * @param program program
	 * @param toAddress target address
	 * @return shifted bytes, null if same as un-shifted
	 */
	public static byte[] getShiftedDirectAddressBytes(Program program, Address toAddress) {

		byte[] addressBytes = getDirectAddressBytes(program, toAddress);

		Memory memory = program.getMemory();
		boolean isBigEndian = memory.isBigEndian();

		DataConverter dataConverter;
		if (isBigEndian) {
			dataConverter = new BigEndianDataConverter();
		}
		else {
			dataConverter = new LittleEndianDataConverter();
		}

		byte[] shiftedAddressBytes = null;
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		DataOrganization dataOrganization = dataTypeManager.getDataOrganization();
		int addressShiftAmount = dataOrganization.getPointerShift();
		if (addressShiftAmount != 0 && program.getDefaultPointerSize() == addressBytes.length) {
			long addrLong = toAddress.getAddressableWordOffset();
			long mask = (-1 >> addressShiftAmount) << addressShiftAmount;
			if ((addrLong & mask) == addrLong) { // make sure use of shift is valid
				shiftedAddressBytes = new byte[addressBytes.length];
				addrLong = addrLong >> addressShiftAmount;
				byte[] tmpBytes = new byte[8];
				dataConverter.getBytes(addrLong, tmpBytes);
				System.arraycopy(tmpBytes,
					isBigEndian ? (tmpBytes.length - addressBytes.length) : 0, shiftedAddressBytes,
					0, shiftedAddressBytes.length);
			}
		}

		return shiftedAddressBytes;
	}

	public static byte[] getImageBaseOffsets32Bytes(Program program, int alignment,
			Address toAddress) {

		Address imageBase = program.getImageBase();

		long offsetValue = toAddress.subtract(imageBase);
		int offsetSize = 4; // 32 bit offset
		byte[] bytes = new byte[offsetSize];
		for (int i = 0; i < offsetSize; i++) {
			bytes[i] = (byte) offsetValue;
			offsetValue >>= 8; // Shift by a single byte.
		}

		return bytes;
	}

	/**
	 * Checks a programs memory for 32 bit image base offset references to the address 
	 * indicated.  These relative references are only found at addresses that match the 
	 * indicated alignment. 
	 * 
	 * @param program the program whose memory is to be checked.
	 * @param alignment 32 bit image base offset relative references are to only be found 
	 * at the indicated alignment in memory.
	 * @param toAddress address that we are interested in finding references to.
	 * @param monitor a task monitor for progress or to allow canceling.
	 * @return list of addresses with 32 bit image base offset relative references to the 
	 * toAddress
	 * 
	 * @throws CancelledException if the user cancels via the monitor.
	 */
	public static Set<Address> findImageBaseOffsets32(Program program, int alignment,
			Address toAddress, TaskMonitor monitor) throws CancelledException {

		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}

		Memory memory = program.getMemory();

		Address imageBase = program.getImageBase();

		long offsetValue = toAddress.subtract(imageBase);
		int offsetSize = 4; // 32 bit offset
		byte[] bytes = new byte[offsetSize];
		for (int i = 0; i < offsetSize; i++) {
			bytes[i] = (byte) offsetValue;
			offsetValue >>= 8; // Shift by a single byte.
		}

		Set<Address> iboRefsAddrs = new TreeSet<>();

		findBytePattern(memory, (AddressRange) null, bytes, alignment, iboRefsAddrs, monitor);

		return iboRefsAddrs;
	}

	//TODO: maybe add param for segment check - leave memory range to limit search
	// this is for the case where the segment is different but the absolute address the same.
	private static void findBytePattern(Memory memory, AddressRange memoryRange, byte[] bytePattern,
			int alignment, Set<Address> foundList, TaskMonitor monitor) throws CancelledException {

		byte maskBytes[] = null;

		MemoryBlock[] blocks = memory.getBlocks();
		for (MemoryBlock block : blocks) {
			if (!block.isInitialized()) {
				continue;
			}
			if (memoryRange != null && !memoryRange.intersects(block.getStart(), block.getEnd())) {
				// skip blocks which do not correspond to currentSeg
				continue;
			}

			Address start = block.getStart();
			Address end = block.getEnd();
			Address found = null;
			while (true) {
				monitor.checkCanceled();

				found = memory.findBytes(start, end, bytePattern, maskBytes, true, monitor);
				if (found == null) {
					break;
				}

				start = found.add(1);
				if (memoryRange != null && !memoryRange.contains(found)) {
					continue;
				}
				if ((found.getOffset() % alignment) == 0) {
					foundList.add(found);
				}
			}
		}
	}

	private static void findBytePattern(Memory memory, List<MemoryBlock> blocks, byte[] bytePattern,
			int alignment, Set<Address> foundList, TaskMonitor monitor) throws CancelledException {

		byte maskBytes[] = null;

		if (blocks == null) {
			blocks = Arrays.asList(memory.getBlocks());
		}

		for (MemoryBlock memBlock : blocks) {
			if (!memBlock.isInitialized()) {
				continue;
			}

			Address start = memBlock.getStart();
			Address end = memBlock.getEnd();
			while (true) {
				monitor.checkCanceled();

				Address found = memory.findBytes(start, end, bytePattern, maskBytes, true, monitor);
				if (found == null) {
					break;
				}

				start = found.add(1);
				if ((found.getOffset() % alignment) == 0) {
					foundList.add(found);
				}
			}
		}
	}
    
	/**
	 * Finds the string in memory indicated by the searchString limited to the indicated 
	 * memory blocks and address set.
	 * @param searchString the string to find
	 * @param program the program to search
	 * @param blocks the only blocks to search
	 * @param set a set of the addresses to limit the results
	 * @param monitor a task monitor to allow 
	 * @return a list of addresses where the string was found
	 * @throws CancelledException if the user cancels
	 */
	public static List<Address> findString(String searchString, Program program,
			List<MemoryBlock> blocks, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
	    
	    List<Address> addresses = new ArrayList<>();
	    
	    // just add each found location to the list, no termination of search
        TerminatingConsumer<Address> collector = (i) -> addresses.add(i);
		
		locateString(searchString, collector, program, blocks, set, monitor);
		
		return addresses;
	}

	/**
	 * Finds the string in memory indicated by the searchString limited to the indicated 
	 * memory blocks and address set.  Each found location calls the foundLocationConsumer.consume(addr)
	 * method.  If the search should terminate, (ie. enough results found), then terminateRequested() should
	 * return true.  Requesting termination is different than a cancellation from the task monitor.
	 * 
	 * @param searchString the string to find
	 * @param foundLocationConsumer location consumer with consumer.accept(Address addr) routine defined
	 * @param program the program to search
	 * @param blocks the only blocks to search
	 * @param set a set of the addresses to limit the results
	 * @param monitor a task monitor to allow 
	 * @throws CancelledException if the user cancels
	 */
	public static void locateString(String searchString, TerminatingConsumer<Address> foundLocationConsumer, Program program,
			List<MemoryBlock> blocks, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {

		monitor.setMessage("Finding \"" + searchString + "\".");
		int length = searchString.length();
		byte[] bytes = searchString.getBytes();
		Memory memory = program.getMemory();
		for (MemoryBlock memoryBlock : blocks) {
			monitor.checkCanceled();
			Address startAddress = memoryBlock.getStart();
			Address endAddress = memoryBlock.getEnd();
			Address foundAddress;
			do {
				monitor.setMessage("Finding \"" + searchString + "\" @ " + startAddress + ".");
				foundAddress =
					memory.findBytes(startAddress, endAddress, bytes, null, true, monitor);
				if (foundAddress == null) {
					break; // no more found in block.
				}
				if (set.contains(foundAddress)) {
					foundLocationConsumer.accept(foundAddress);
					if (foundLocationConsumer.terminationRequested()) {
						return; // termination of search requested
					}
				}
				try {
					startAddress = foundAddress.add(length);
				}
				catch (AddressOutOfBoundsException e) {
					break; // At end of block.
				}
			}
			while (startAddress.compareTo(endAddress) <= 0);
		}
	}

	/**
	 * Gets a list of memory blocks whose name starts with the indicated name. Only memory 
	 * blocks that are initialized  and part of the indicated address set will be returned.
	 * @param program the program for obtaining the memory blocks
	 * @param set the address set to use to limit the blocks returned
	 * @param name the text which the memory block's name must start with.
	 * @param monitor a status monitor that allows the operation to be cancelled
	 * @return the list of memory blocks
	 * @throws CancelledException if the user cancels
	 */
	public static List<MemoryBlock> getMemoryBlocksStartingWithName(Program program,
			AddressSetView set, String name, TaskMonitor monitor) throws CancelledException {

		List<MemoryBlock> blocks = new ArrayList<>();
		Memory memory = program.getMemory();

		for (MemoryBlock memoryBlock : memory.getBlocks()) {
			monitor.checkCanceled();

			AddressSet blockSet = new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd());
			AddressSet intersection = blockSet.intersect(set);
			if (!intersection.isEmpty() && memoryBlock.isInitialized() &&
				memoryBlock.getName().startsWith(name)) {

				blocks.add(memoryBlock);
			}
		}
		return blocks;
	}
}

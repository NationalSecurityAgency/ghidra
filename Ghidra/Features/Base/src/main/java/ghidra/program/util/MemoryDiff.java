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

import java.util.ArrayList;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * <CODE>MemoryDiff</CODE> determines where the memory differs between two programs as well as the
 * types of differences.
 */
public class MemoryDiff {
	
	private Program program1;
	private Program program2;
	private Memory memory1;
	private Memory memory2;
	private AddressRange[] ranges;
	private MemoryBlockDiff[] diffs;
	
	/**
	 * Constructs an object for determining memory differences between two programs.
	 * @param p1 the first program
	 * @param p2 the second program
	 * @throws ProgramConflictException if the program memory can't be compared because the programs
	 * are based on different languages.
	 */
	public MemoryDiff(Program p1, Program p2)
	throws ProgramConflictException {
		program1 = p1;
		program2 = p2;
		memory1 = program1.getMemory();
		memory2 = program2.getMemory();
		computeRanges();
		computeDifferences();
	}
	
	/**
	 * Gets the first program that is part of this MemoryDiff.
	 * @return the first program
	 */
	public Program getProgram1() {
		return program1;
	}
	
	/**
	 * Gets the second program that is part of this MemoryDiff.
	 * @return the second program
	 */
	public Program getProgram2() {
		return program2;
	}
	
	/**
	 * Determines the address ranges that the two programs memories must be broken into for 
	 * properly comparing the programs. Each of these address ranges will exist in the first
	 * program, the second program or both programs.
	 * @throws ProgramConflictException if the two programs can't be compared.
	 */
	private void computeRanges() throws ProgramConflictException {
		ProgramMemoryComparator memComp = new ProgramMemoryComparator(program1, program2);
		ArrayList<AddressRange> rangeList = new ArrayList<AddressRange>();
		AddressRangeIterator rangeIter = memComp.getAddressRanges();
		while(rangeIter.hasNext()) {
			rangeList.add(rangeIter.next());
		}
		ranges = rangeList.toArray(new AddressRange[rangeList.size()]);
	}
	
	/**
	 * Gets the number of address ranges that the two programs memories are broken into for 
	 * comparing the programs.
	 * @return the number of address ranges.
	 */
	public int getNumRanges() {
		return ranges.length;
	}
	
	/**
	 * Gets the address range as indicated by index. The index is zero based. Address ranges are
	 * in order from the minimum address to the maximum address range.
	 * @param index the index of the address range to get.
	 * @return the address range.
	 */
	public AddressRange getRange(int index) {
		return ranges[index];
	}
	
	/**
	 * Gets the memory difference flags for the address range as indicated by index.
	 * @param index the index of the address range to get the difference flags for.
	 * @return the difference flags for the indicated address range.
	 */
	public MemoryBlockDiff getDifferenceInfo(int index) {
		return diffs[index];
	}
	
	/**
	 * Determines the memory differences and sets the flags for each associated address range.
	 */
	private void computeDifferences() {
		diffs = new MemoryBlockDiff[ranges.length];
		for (int i = 0; i < ranges.length; i++) {
			Address addr = ranges[i].getMinAddress();
			MemoryBlock block1 = memory1.getBlock(addr);
			MemoryBlock block2 = memory2.getBlock(addr);
			diffs[i] = new MemoryBlockDiff(block1, block2);
		}
	}
	
	/**
	 * Gets a string representation of the types of memory differences that exist for the memory 
	 * block that contains the indicated address.
	 * @param p1Address address that is obtained via the first program.
	 * @return a string indicating the types of memory differences.
	 */
	public String getDifferences(Address p1Address) {
		int index = getAddressRangeIndex(p1Address);
		if (index < 0 || index >= diffs.length) {
			return null;
		}
		MemoryBlockDiff info = getDifferenceInfo(index);
		return info.getDifferencesAsString();
	}
	
	/**
	 * Gets the index of the address range containing the indicated address, 
	 * if it is contained in the list;
     *	       otherwise, <tt>(-(<i>insertion point</i>) - 1)</tt>.
	 * @param address the address whose range we are interested in finding.
	 * @return the index of the address range.
	 */
	private int getAddressRangeIndex(Address address) {
		int low = 0;
		int high = diffs.length-1;
	
		while (low <= high) {
		    int mid = (low + high) >> 1;
		    AddressRange range = ranges[mid];
		    if (range.contains(address)) {
		    	return mid;
		    }
		    else if (address.compareTo(range.getMinAddress()) < 0) {
		    	high = mid - 1;
		    }
		    else {
		    	low = mid + 1;
		    }
		}
		return -(low + 1);  // not found.
	}

	/**
	 * Returns an array of address ranges where there are memory differences.
	 * @return address ranges with differences.
	 */
	public AddressRange[] getDifferentAddressRanges() {
		ArrayList<AddressRange> rangeDiffs = new ArrayList<AddressRange>();
		for (AddressRange range : ranges) {
			Address addr = range.getMinAddress();
			MemoryBlock block1 = memory1.getBlock(addr);
			MemoryBlock block2 = memory2.getBlock(addr);
			if (!sameMemoryBlock(block1, block2)) {
				rangeDiffs.add(range);
			}
		}
		return rangeDiffs.toArray(new AddressRange[rangeDiffs.size()]);
	}
	
	/**
	 * Determines whether the two memory blocks are the same.
	 * @param block1 the first program's memory block
	 * @param block2 the second program's memory block
	 * @return true if the memory blocks are the same.
	 */
	private boolean sameMemoryBlock(MemoryBlock block1, MemoryBlock block2) {
		if (block1 == null) {
			return (block2 == null);
		}
		else if (block2 == null) {
			return false;
		}
		if(!block1.getName().equals(block2.getName())) {
			return false;
		}
		if (!block1.getStart().equals(block2.getStart())) {
			return false;
		}
		if (!block1.getEnd().equals(block2.getEnd())) {
			return false;
		}
		if (block1.getSize() != block2.getSize()) {
			return false;
		}
		if (block1.getPermissions() != block2.getPermissions()) {
			return false;
		}
		if (!block1.getType().equals(block2.getType())) {
			return false;
		}
		if (block1.isInitialized() != block2.isInitialized()) {
			return false;
		}
		if (!SystemUtilities.isEqual(block1.getSourceName(), block2.getSourceName())) {
			return false;
		}
		if (!SystemUtilities.isEqual(block1.getComment(), block2.getComment())) {
			return false;
		}
		if (block1.isMapped() != block2.isMapped()) {
			return false;
		}
		return true;
	}
	
	
	public boolean merge(int row, int mergeFields, TaskMonitor monitor) {
		if ((mergeFields & MemoryBlockDiff.ALL) == 0) {
			return false;
		}
		if (row < 0 || row >= diffs.length) {
			return false;
		}
		MemoryBlockDiff blockDiff = diffs[row];
		MemoryBlock block1 = blockDiff.getBlock1();
		MemoryBlock block2 = blockDiff.getBlock2();
		AddressRange range = ranges[row];
		if (shouldMerge(mergeFields, MemoryBlockDiff.START_ADDRESS)
		            && blockDiff.isStartAddressDifferent()) {
			if (block1 == null) {
				// Add all or part of a block.
				Address start2 = block2.getStart();
				Address end2 = block2.getEnd();
				Address startRange = range.getMinAddress();
				Address endRange = range.getMaxAddress();
				int compareStart = start2.compareTo(startRange);
				int compareEnd = end2.compareTo(endRange);
				try {
					memory1.createBlock(block2, block2.getName(), startRange, range.getLength());
					if (compareStart < 0) {
						MemoryBlock firstBlock = memory1.getBlock(start2);
						MemoryBlock secondBlock = memory1.getBlock(startRange);
						memory1.join(firstBlock, secondBlock);
					}
					if (compareEnd > 0) {
						MemoryBlock firstBlock = memory1.getBlock(endRange);
						MemoryBlock secondBlock = memory1.getBlock(end2);
						memory1.join(firstBlock, secondBlock);
					}
					return true;
				}
				catch (Exception e) {
				    Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
				return false;
			}
			if (block2 == null) {
				// Remove all or part of a block.
				Address start1 = block1.getStart();
				Address end1 = block1.getEnd();
				Address startRange = range.getMinAddress();
				Address endRange = range.getMaxAddress();
				int compareStart = start1.compareTo(startRange);
				int compareEnd = end1.compareTo(endRange);
				try {
					if (compareEnd > 0) {
						memory1.split(block1, endRange.add(1L));
					}
					if (compareStart < 0) {
						memory1.split(block1, startRange);
					}
					if (compareStart == 0 && compareEnd == 0) {
						MemoryBlock blockToRemove = memory1.getBlock(startRange);
						memory1.removeBlock(blockToRemove, monitor);
					}
					return true;
				} catch (LockException e) {
				    Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				} catch (NotFoundException e) {
				    Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				} catch (AddressOutOfBoundsException e) {
				    Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				} catch (MemoryBlockException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
				return false;
			}
		}
		if (shouldMerge(mergeFields, MemoryBlockDiff.END_ADDRESS)
		    && blockDiff.isEndAddressDifferent()) {
			// TODO
		}
		if (shouldMerge(mergeFields, MemoryBlockDiff.SIZE)
		    && blockDiff.isSizeDifferent()) {
			// TODO
		}
		if (shouldMerge(mergeFields, MemoryBlockDiff.TYPE)
		    && blockDiff.isTypeDifferent()) {
			// TODO
		}
		if (shouldMerge(mergeFields, MemoryBlockDiff.INIT)
		    && blockDiff.isInitDifferent()) {
			// TODO
		}
		if (shouldMerge(mergeFields, MemoryBlockDiff.NAME)
				    && blockDiff.isNameDifferent()) {
			try {
				block1.setName(block2.getName());
			} catch (LockException e) {
			    Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
		}
		if (shouldMerge(mergeFields, MemoryBlockDiff.READ)
		    && blockDiff.isReadDifferent()) {
			block1.setRead(block2.isRead());
		}
		if (shouldMerge(mergeFields, MemoryBlockDiff.WRITE)
		    && blockDiff.isWriteDifferent()) {
			block1.setWrite(block2.isWrite());
		}
		if (shouldMerge(mergeFields, MemoryBlockDiff.EXECUTE)
		    && blockDiff.isExecDifferent()) {
			block1.setExecute(block2.isExecute());
		}
		if (shouldMerge(mergeFields, MemoryBlockDiff.VOLATILE)
		    && blockDiff.isVolatileDifferent()) {
			block1.setVolatile(block2.isVolatile());
		}
		if (shouldMerge(mergeFields, MemoryBlockDiff.SOURCE)
		    && blockDiff.isSourceDifferent()) {
			block1.setSourceName(block2.getSourceName());
		}
		if (shouldMerge(mergeFields, MemoryBlockDiff.COMMENT)
		    && blockDiff.isCommentDifferent()) {
			block1.setComment(block2.getComment());
		}
		return true;
	}

	private boolean shouldMerge(int mergeFields, int memDiffType) {
		return ((mergeFields & memDiffType) != 0);
	}
}

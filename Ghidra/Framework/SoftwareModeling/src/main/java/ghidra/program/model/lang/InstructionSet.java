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
package ghidra.program.model.lang;

import java.util.*;

import ghidra.program.database.register.AddressRangeObjectMap;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Instruction;
import ghidra.util.exception.AssertException;

/** 
 * A set of instructions organized as a graph of basic blocks. 
 */
public class InstructionSet implements Iterable<InstructionBlock> {
	private Map<Address, InstructionBlock> blockMap = new HashMap<Address, InstructionBlock>();
	private AddressRangeObjectMap<InstructionBlock> blockRangeMap =
		new AddressRangeObjectMap<InstructionBlock>();
	private Set<Address> startAddresses = new HashSet<Address>();
	private List<InstructionBlock> emptyBlocks = new ArrayList<InstructionBlock>();
	private AddressSet addressSet;
	private int instructionCount = 0;

	public InstructionSet(AddressFactory addrFactory) {
		addressSet = new AddressSet();
	}

	/**
	 * Add an Instruction block to this Instruction Set. 
	 * If the block is empty it will only be added to the empty-list and will not
	 * be added to the maps or block iterator
	 * @param block the block to add.
	 */
	public void addBlock(InstructionBlock block) {
		if (block.isEmpty()) {
			// multiple empty blocks at the same address are possible
			emptyBlocks.add(block);
			return;
		}
		if (block.isFlowStart() || blockRangeMap.getObject(block.getFlowFromAddress()) == null) {
			startAddresses.add(block.getStartAddress());
		}
		InstructionBlock oldBlock = blockMap.put(block.getStartAddress(), block);
		if (oldBlock != null && oldBlock != block) {
			throw new AssertException("More than one block exists with the same start address");
		}
		addressSet.addRange(block.getStartAddress(), block.getMaxAddress());
		instructionCount += block.getInstructionCount();
		blockRangeMap.setObject(block.getStartAddress(), block.getMaxAddress(), block);
	}

	/**
	 * Returns the non-empty InstructionBlock containing the specified address
	 * @param address
	 * @return the InstructionBlock containing the specified address or null if not found
	 */
	public InstructionBlock getInstructionBlockContaining(Address address) {
		InstructionBlock block = blockRangeMap.getObject(address);
		if (block != null) {
			return block;
		}
		// try returning an empty block if one exists
		return blockMap.get(address);
	}

	/**
	 * Find the first block within this InstructionSet which intersects the specified range.
	 * This method should be used sparingly since it uses a brute-force search.
	 * @param min the minimum intersection address
	 * @param max the maximum intersection address
	 * @return block within this InstructionSet which intersects the specified range or null
	 * if not found 
	 */
	public InstructionBlock findFirstIntersectingBlock(Address min, Address max) {
		InstructionBlock intersectBlock = null;
		for (InstructionBlock block : blockMap.values()) {
			Address blockMin = block.getStartAddress();
			if (blockMin.compareTo(max) > 0) {
				continue;
			}
			Address blockMax = block.getMaxAddress();
			if (blockMax.compareTo(min) < 0) {
				continue;
			}
			if (intersectBlock != null && intersectBlock.getStartAddress().compareTo(blockMin) < 0) {
				continue;
			}
			intersectBlock = block;
		}
		return intersectBlock;
	}

	/**
	 * Returns the instruction at the specified address within this instruction set
	 * @param address
	 * @return instruction at the specified address within this instruction set or null if not found
	 */
	public Instruction getInstructionAt(Address address) {
		InstructionBlock block = getInstructionBlockContaining(address);
		return block != null ? block.getInstructionAt(address) : null;
	}

	/**
	 * Returns the minimum address for this Instruction set;
	 * @return the minimum address for this Instruction set;
	 */
	public Address getMinAddress() {
		return addressSet.getMinAddress();
	}

	/**
	 * Returns the address set that makes up all the instructions contained in this set.
	 * @return  the address set that makes up all the instructions contained in this set.
	 */
	public AddressSetView getAddressSet() {
		return addressSet;
	}

	@Override
	public String toString() {
		return addressSet.toString();
	}

	/**
	 * Returns the number of instructions in this instruction set.
	 * @return the number of instructions in this instruction set.
	 */
	public int getInstructionCount() {
		return instructionCount;
	}

	public boolean containsBlockAt(Address blockAddr) {
		return blockMap.containsKey(blockAddr);
	}

	/**
	 * Returns true if this instruction set intersects the specified range
	 * @param minAddress
	 * @param maxAddress
	 * @return true if this instruction set intersects the specified range
	 */
	public boolean intersects(Address minAddress, Address maxAddress) {
		return addressSet.intersects(minAddress, maxAddress);
	}

	/**
	 * Returns an iterator over the blocks in this Instruction set, giving preference to fall
	 * through flows.  This iterator will not follow any flows from a block that has a conflict.
	 * If the last block returned from the iterator is marked as a conflict before the next() or
	 * hasNext() methods are called, then this iterator will respect the conflict.  In other words,
	 * this iterator follows block flows on the fly and doesn't pre-compute the blocks to return.  
	 * Also, if any blocks in this set don't have a flow to path from the start block, it will
	 * not be included in this iterator.
	 */
	@Override
	public Iterator<InstructionBlock> iterator() {
		return new BlockIterator();
	}

	/**
	 * Returns an iterator over all empty blocks which likely contain a conflict error.
	 * @return empty block iterator
	 */
	public Iterator<InstructionBlock> emptyBlockIterator() {
		return emptyBlocks.iterator();
	}

	/**
	 * Returns a list of conflicts for this set.  If a block is not reachable from a non-conflicted
	 * block, it's conflicts(if any) will not be included.
	 * @return the list of conflicts for this set.
	 */
	public List<InstructionError> getConflicts() {
		List<InstructionError> conflictList = new ArrayList<InstructionError>();
		for (InstructionBlock block : this) {
			if (block.hasInstructionError()) {
				conflictList.add(block.getInstructionConflict());
			}
		}
		return conflictList;
	}

	class BlockIterator implements Iterator<InstructionBlock> {
		private InstructionBlock currentBlock;
		private Set<Address> visitedBlockSet = new HashSet<Address>();
		private FlowQueue flowQueue = new FlowQueue();

		BlockIterator() {
			for (Address startAddr : startAddresses) {
				flowQueue.add(startAddr);
			}
		}

		@Override
		public boolean hasNext() {
			if (flowQueue.isEmpty()) {
				addFlows(currentBlock);
			}
			return !flowQueue.isEmpty();
		}

		@Override
		public InstructionBlock next() {
			addFlows(currentBlock);

			currentBlock = flowQueue.isEmpty() ? null : blockMap.get(flowQueue.removeNext());

			if (currentBlock != null) {
				visitedBlockSet.add(currentBlock.getStartAddress());
			}

			return currentBlock;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException("Remove is not supported for this iterator");
		}

		private void addFlows(InstructionBlock block) {
			if (block == null) {
				return;
			}
			if (!block.hasInstructionError()) {
				// Only add fall-through flow if block has no conflict
				Address fallThrough = block.getFallThrough();
				if (fallThrough != null && !startAddresses.contains(fallThrough) &&
					isNotVisitedAndHasBlock(fallThrough)) {
					flowQueue.addToFront(fallThrough);
				}
			}
			Address conflictAddr = null;
			if (block.hasInstructionError()) {
				conflictAddr = block.getInstructionConflict().getInstructionAddress();
				if (conflictAddr == null) {
					return;
				}
			}
			for (Address address : block.getBranchFlows()) {
				if (!startAddresses.contains(address) && isNotVisitedAndHasBlock(address) &&
					flowsFromBeforeCutoff(address, conflictAddr)) {
					flowQueue.add(address);
				}
			}
		}

		private boolean flowsFromBeforeCutoff(Address blockAddr, Address cutoffAddr) {
			if (cutoffAddr == null) {
				return true;
			}
			InstructionBlock block = blockMap.get(blockAddr);
			if (block == null) {
				return false; // block not available
			}
			return block.getFlowFromAddress().compareTo(cutoffAddr) < 0;
		}

		private boolean isNotVisitedAndHasBlock(Address blockAddr) {
			if (visitedBlockSet.contains(blockAddr)) {
				return false;
			}
			return blockMap.containsKey(blockAddr);
		}
	}

	static class FlowQueue {
		private SortedSet<Address> set = new TreeSet<Address>();
		private Address first;

		void addToFront(Address address) {
			set.add(address);
			first = address;
		}

		void add(Address address) {
			set.add(address);
		}

		boolean contains(Address address) {
			return set.contains(address);
		}

		boolean isEmpty() {
			return set.isEmpty();
		}

		Address removeNext() {
			Address next = first;
			first = null;
			if (next == null) {
				next = set.first();
			}
			set.remove(next);
			return next;
		}
	}

}

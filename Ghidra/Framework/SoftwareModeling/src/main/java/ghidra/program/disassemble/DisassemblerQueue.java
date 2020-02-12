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
package ghidra.program.disassemble;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.lang.InstructionBlockFlow.Type;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

class DisassemblerQueue {

	//
	// All flow queues are order using the ORDERED_FLOW_COMPARATOR
	//

	// orderedSeedQueue contains initial start points and discovered CALL points
	private TreeSet<InstructionBlockFlow> orderedSeedQueue;

	// priorityBranchQueue corresponds to those branch flows discovered by previous instruction sets
	// which must take priority over newly discovered branch points within the current instruction set
	// and takes priority over the orderedSeedQueue
	private TreeSet<InstructionBlockFlow> priorityQueue;

	// currentBranchQueue corresponds to those branch flows discovered within the current instruction set
	// which should be processed only when priorityBranchQueue is empty.  This queue will be cleared
	// after each InstructionSet is generated - any valid flows from the InstructionSet not yet
	// processed will be added to the priorityBranchQueue for inclusion in subsequent InstructionSets
	private TreeSet<InstructionBlockFlow> currentBranchQueue;

	// newly discovered branch flows within the current instruction set which were processed
	// within the current instruction set.  Cleared before next InstructionSet is processed.
	private HashSet<InstructionBlockFlow> processedBranchFlows;

	private AddressSetView restrictedAddressSet;
	private InstructionBlock lastBlock;
	private Address lastBlockAddr;
	private Address lastFlowFrom;

	private static final Comparator<InstructionBlockFlow> ORDERED_FLOW_COMPARATOR =
		new Comparator<InstructionBlockFlow>() {

			@Override
			public int compare(InstructionBlockFlow o1, InstructionBlockFlow o2) {
				int c = o1.getType().ordinal() - o2.getType().ordinal();
				if (c == 0) {
					c = o1.getDestinationAddress().compareTo(o2.getDestinationAddress());
				}
				return c;
			}
		};

	/**
	 * Constructor
	 */
	DisassemblerQueue(Address startAddr, AddressSetView restrictedAddressSet) {

		this.restrictedAddressSet = restrictedAddressSet;

		orderedSeedQueue = new TreeSet<InstructionBlockFlow>(ORDERED_FLOW_COMPARATOR);
		priorityQueue = new TreeSet<InstructionBlockFlow>(ORDERED_FLOW_COMPARATOR);
		currentBranchQueue = new TreeSet<InstructionBlockFlow>(ORDERED_FLOW_COMPARATOR);
		processedBranchFlows = new HashSet<InstructionBlockFlow>(48);

		orderedSeedQueue.add(
			new InstructionBlockFlow(startAddr, null, InstructionBlockFlow.Type.PRIORITY));
	}

	/**
	 * Determine if additional InstructionSets may be produced.  If true is returned,
	 * this queue will be ready to produce InstructionSet blocks.
	 * @param monitor cancellable task monitor 
	 * @return true if additional InstructionSets may be produced
	 */
	boolean continueProducingInstructionSets(TaskMonitor monitor) {

		currentBranchQueue.clear();
		processedBranchFlows.clear();
		lastBlock = null;
		lastBlockAddr = null;
		lastFlowFrom = null;

		if (monitor != null && monitor.isCancelled()) {
			return false;
		}

		if (!priorityQueue.isEmpty()) {
			return true;
		}

		if (orderedSeedQueue.isEmpty()) {
			return false;
		}

		InstructionBlockFlow flow = orderedSeedQueue.first();
		orderedSeedQueue.remove(flow);
		priorityQueue.add(flow);
		return true;
	}

	/**
	 * Return next block to disassemble for the current InstructionSet.
	 * @param fallThruAddr specifies the next instruction to be disassembled if the 
	 * previous instruction had a fall-through.  If specified, the previous block 
	 * will be return.  If null, the next block to be disassembled will be returned. 
	 * @param memory needed for normalization of SegementedAddresses (may be null).
	 * @param monitor cancellable task monitor 
	 * @return next block to be disassembled or null if no more queued flows to process
	 * for current InstructionSet, or remaining flows fall outside restricted address set,
	 * monitor has cancelled disassembly.
	 */
	InstructionBlock getNextBlockToBeDisassembled(Address fallThruAddr, Memory memory,
			TaskMonitor monitor) {

		if (monitor != null && monitor.isCancelled()) {
			lastBlock = null;
			return null;
		}

		if (fallThruAddr != null) {
			if (lastBlock == null) {
				throw new IllegalStateException();
			}
			// no state change fallThruAddr is 
			if (fallThruAddr.equals(lastBlockAddr)) {
				return lastBlock;
			}
			// fallthrough within block - continue disassembly of last block
			lastFlowFrom = lastBlockAddr;
			lastBlockAddr = fallThruAddr;

			if (checkMemoryRestriction(fallThruAddr)) {
				lastFlowFrom = lastBlockAddr;
				lastBlockAddr = fallThruAddr;
				return lastBlock;
			}
		}

		lastBlock = null;
		lastBlockAddr = null;
		lastFlowFrom = null;

		while ((monitor == null || !monitor.isCancelled()) &&
			(fallThruAddr != null || !priorityQueue.isEmpty() || !currentBranchQueue.isEmpty())) {

			// Prepare new block using next queued flow
			boolean forcedStartOfFlow = false;
			InstructionBlockFlow branchFlow = null;
			if (!priorityQueue.isEmpty()) {
				branchFlow = priorityQueue.first();
				priorityQueue.remove(branchFlow);
				// must force start of flow within InstructionSet so that this flow
				// is not dependent upon a flow-from block within the InstructionSet
				forcedStartOfFlow = true;
			}
			else if (!currentBranchQueue.isEmpty()) {
				branchFlow = currentBranchQueue.first();
				currentBranchQueue.remove(branchFlow);
			}
			processedBranchFlows.add(branchFlow);

			Address blockAddr = branchFlow.getDestinationAddress();
			if (blockAddr instanceof SegmentedAddress) {
				blockAddr = normalize((SegmentedAddress) blockAddr, memory);
			}

			if (checkMemoryRestriction(blockAddr)) {
				lastBlockAddr = blockAddr;
				lastFlowFrom = branchFlow.getFlowFromAddress();
				lastBlock = new InstructionBlock(lastBlockAddr);
				lastBlock.setFlowFromAddress(lastFlowFrom);
				lastBlock.setStartOfFlow(forcedStartOfFlow);
				break;
			}
		}
		return lastBlock;
	}

	/**
	 * 
	 * @param instructionSet
	 * @return number of instructions added to program
	 */
	int instructionSetAddedToProgram(InstructionSet instructionSet,
			DisassemblerConflictHandler conflictHandler) {

		int disassembleCount = 0;

		AddressSet conflictAddrs = new AddressSet();

		// check for disassembly errors and deferred call queuing
		for (InstructionBlock block : instructionSet) {
			InstructionError conflict = block.getInstructionConflict();
			if (conflict != null) {
				// mark disassembly error
				conflictHandler.markInstructionError(conflict);
				Address conflictAddr = conflict.getInstructionAddress();
				Address blockEndAddr = block.getMaxAddress();
				// add portion of block not added to conflictAddrs
				if (conflictAddr.compareTo(blockEndAddr) <= 0) {
					conflictAddrs.addRange(conflictAddr, blockEndAddr);
				}
			}

			int instrCount = block.getInstructionsAddedCount();
			if (instrCount == 0) {
				continue;
			}

			// Add deferred flows for instructions which were successfully added
			List<InstructionBlockFlow> blockFlows = block.getBlockFlows();
			if (blockFlows != null) {
				for (InstructionBlockFlow blockFlow : blockFlows) {
					Type flowType = blockFlow.getType();
					if (flowType != Type.CALL && processedBranchFlows.contains(blockFlow)) {
						continue;
					}
					if (conflict == null || conflict.getInstructionAddress().compareTo(
						blockFlow.getFlowFromAddress()) > 0) {
						// Add good flows to priorityBranchSet to ensure that future context is
						// properly consumed with a guaranteed block start.  We don't
						// want block to be dependent upon a parent block
						if (flowType == Type.CALL) {
							orderedSeedQueue.add(blockFlow);
						}
						else {
							priorityQueue.add(blockFlow);
						}
					}
				}
			}
			disassembleCount += instrCount;
		}

		// check for empty block errors
		Iterator<InstructionBlock> emptyBlockIterator = instructionSet.emptyBlockIterator();
		while (emptyBlockIterator.hasNext()) {
			InstructionBlock emptyBlock = emptyBlockIterator.next();
			Address flowFromAddress = emptyBlock.getFlowFromAddress();
			if (flowFromAddress != null && conflictAddrs.contains(flowFromAddress)) {
				continue; // skip if flow from instruction was never added
			}
			InstructionError conflict = emptyBlock.getInstructionConflict();
			if (conflict != null) {
				conflictHandler.markInstructionError(conflict);
			}
		}

		return disassembleCount;
	}

	Address getDisassemblyAddress() {
		return lastBlockAddr;
	}

	Address getDisassemblyFlowFromAddress() {
		return lastFlowFrom;
	}

	/**
	 * Queue priority delay-slot disassembly for current block.
	 * Fallthrough must be handled immediately with next InstructionSet
	 * to ensure that it remains the start of an InstructionBlock contained 
	 * within current InstructionSet.
	 * Caller is responsible for adding flow to current block.
	 * @param flow instruction flow
	 */
	void queueDelaySlotFallthrough(Instruction delaySlotInstruction) {
		InstructionBlockFlow dsFallThrough =
			new InstructionBlockFlow(delaySlotInstruction.getMaxAddress().next(),
				delaySlotInstruction.getAddress(), InstructionBlockFlow.Type.PRIORITY);
		priorityQueue.add(dsFallThrough);
	}

	/**
	 * Queue specified flow for processing within current InstructionSet.
	 * Caller is responsible for adding flow to current block.
	 * @param flow instruction flow
	 */
	void queueCurrentFlow(InstructionBlockFlow flow) {
		// TODO: do we need to defer this longer? i.e., outside current IntructionSet
		currentBranchQueue.add(flow);
	}

	private boolean checkMemoryRestriction(Address addr) {
		return (restrictedAddressSet == null || restrictedAddressSet.contains(addr));
	}

	private Address normalize(SegmentedAddress addr, Memory memory) {
		if (memory == null) {
			return addr;
		}
		MemoryBlock block = memory.getBlock(addr);
		if (block == null) {
			return addr;
		}
		SegmentedAddress start = (SegmentedAddress) block.getStart();
		return addr.normalize(start.getSegment());

	}

}

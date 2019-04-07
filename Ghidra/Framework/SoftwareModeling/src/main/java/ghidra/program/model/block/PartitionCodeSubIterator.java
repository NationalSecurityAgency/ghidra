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
package ghidra.program.model.block;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.LinkedList;

/**
 * <CODE>PartitionCodeSubIterator</CODE> is an implementation of
 * <CODE>CodeBlockIterator</CODE> capable of iterating in
 * the forward direction over "PartitionCodeSubModel code blocks".
 */
class PartitionCodeSubIterator implements CodeBlockIterator {

	private Listing listing = null;
	// at any given time nextSub will either be null or hold the
	// next block to be returned by next()
	private CodeBlock nextSub = null;

	private InstructionIterator instIter;

	// create a holder for the blockSet
	private AddressSet addrCoveredSoFar = new AddressSet();

	// Available block stack
	private LinkedList<CodeBlock> blockList = new LinkedList<CodeBlock>();

	private PartitionCodeSubModel model = null;
	private TaskMonitor monitor;

	/**
	 * Creates a new iterator that will iterate over the entire
	 * program starting from its current minimum address.
	 *
	 * @param model  the BlockModel the iterator will use in its operations.
	 * @param monitor task monitor which allows user to cancel operation.
	 */
	PartitionCodeSubIterator(PartitionCodeSubModel model, TaskMonitor monitor) {
		this(model, model.getProgram().getMinAddress(), monitor);
	}

	/**
	 * Creates a new iterator that will iterate over the
	 * program starting from a given address.
	 *
	 * @param model  the BlockModel the iterator will use in its operations.
	 * @param addr   the address to start iterating from.
	 * @param monitor task monitor which allows user to cancel operation.
	 */
	PartitionCodeSubIterator(PartitionCodeSubModel model, Address addr, TaskMonitor monitor) {
		this.model = model;
		this.monitor = monitor != null ? monitor : TaskMonitor.DUMMY;
		this.listing = model.getListing();
		this.instIter = listing.getInstructions(addr, true);
		this.nextSub = null;
		this.monitor.setIndeterminate(true);
	}

	/**
	 * Creates a new iterator that will iterate over the
	 * program within a given address range set. A block will
	 * be returned by this iterator if and only if the block's
	 * starting address is within the address range set.  The blocks
	 * themselves may lie outside of set.
	 *
	 * @param model  the SubroutineModel the iterator will use in its operations.
	 * @param set    the address range set which the iterator is to be
	 *               restricted to.
	 * @param monitor task monitor which allows user to cancel operation.
	 */
	PartitionCodeSubIterator(PartitionCodeSubModel model, AddressSetView set, TaskMonitor monitor) {
		this.model = model;
		this.monitor = monitor != null ? monitor : TaskMonitor.DUMMY;
		this.listing = model.getListing();
		this.instIter = listing.getInstructions(set, true);
		this.nextSub = null;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockIterator#hasNext()
	 */
	@Override
	public boolean hasNext() throws CancelledException {

		// Next sub block is already waiting
		if (nextSub != null)
			return true;

		// Check block list for available block
		if (!blockList.isEmpty()) {
			nextSub = blockList.removeFirst();
			if (nextSub != null)
				return true;
		}

		// Iterate over instructions looking for next block
		while (nextSub == null && instIter.hasNext()) {

			Instruction inst = instIter.next();

			// don't iterate over instructions in subroutines already found!
			Address minAddr = inst.getMinAddress();

			if (addrCoveredSoFar.contains(minAddr))
				continue;

			CodeBlock block = model.getFirstCodeBlockContaining(minAddr, monitor);
			if (block != null) {
				addrCoveredSoFar.add(block);
				nextSub = block;
			}
		}
		return (nextSub != null);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockIterator#next()
	 */
	@Override
	public CodeBlock next() throws CancelledException {
		if (nextSub == null)
			hasNext();
		CodeBlock retSub = nextSub;
		nextSub = null;
		return retSub;
	}
}

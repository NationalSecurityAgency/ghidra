/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

/**
 * <CODE>SimpleBlockIterator</CODE> is an implementation of
 * <CODE>CodeBlockIterator</CODE> capable of iterating in
 * the forward direction over "simple blocks".
 * @see SimpleBlockModel
 */
public class SimpleBlockIterator implements CodeBlockIterator {
	private Listing listing = null;
	// at any given time nextBlock will either be null or hold the
	// next block to be returned by next()
	private CodeBlock nextBlock = null;
	// the next block to be found will always be the first one to
	// occur strictly after nextAddr
	private Address nextAddr = null;
	// set by iterators with an address range set restriction
	private AddressSetView addrSet = null;
	// set by iterators with an address range set restriction
	private AddressRangeIterator rangeIter = null;
	private SimpleBlockModel model = null;
	private TaskMonitor monitor;

	/**
	 * Creates a new iterator that will iterate over the entire
	 * program starting from its current minimum address.
	 * <P>
	 *
	 * @param model  the BlockModel the iterator will use in its operations.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	public SimpleBlockIterator(SimpleBlockModel model, TaskMonitor monitor)
			throws CancelledException {
		this(model, model.getProgram().getMemory(), monitor);
	}

	/**
	 * Creates a new iterator that will iterate over the
	 * program within a given address range set. All blocks which 
	 * overlap the address set will be returned.
	 * <P>
	 *
	 * @param model  the BlockModel the iterator will use in its operations.
	 * @param set    the address range set which the iterator is to be
	 *               restricted to.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	public SimpleBlockIterator(SimpleBlockModel model, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {

// ?? ITERATOR HAS BEEN MODIFIED TO ONLY RETURN INSTRUCTION BLOCKS

		this.model = model;
		this.monitor = monitor != null ? monitor : TaskMonitor.DUMMY;
		listing = model.getProgram().getListing();
		addrSet = set;
		rangeIter = set.getAddressRanges();
		nextAddr = set.getMinAddress();
		if (nextAddr == null) {
			nextBlock = null;
		}
		else {
			nextBlock = model.getFirstCodeBlockContaining(nextAddr, monitor);
		}
		if (nextBlock != null) {
			nextAddr = nextBlock.getMaxAddress();
//        	// Data block only included if it references an instruction
			CodeUnit codeUnit = listing.getCodeUnitAt(nextBlock.getMinAddress());
			if (codeUnit instanceof Data) {
//        		if (!dataReferencesInstruction((Data)codeUnit)) {
				nextBlock = null;
//        		}
			}
		}
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockIterator#hasNext()
	 */
	@Override
	public boolean hasNext() throws CancelledException {
		if (nextBlock != null) {
			return true;
		}

		getNextInSet();

		return (nextBlock != null);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockIterator#next()
	 */
	@Override
	public CodeBlock next() throws CancelledException {
		if (nextBlock == null) {
			hasNext();
		}
		CodeBlock retBlock = nextBlock;
		nextBlock = null;
		return retBlock;
	}

	/**
	 * Called for iterators restricted by an address range set,
	 * it will find the next block and set up nextBlock and
	 * nextAddr accordingly.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	private void getNextInSet() throws CancelledException {
		// find next address that has a valid block;
		Address addr = getNextAddress(nextAddr);

		// if the instruction's start address is in our set
		// then we have our block
		if (addr != null && addrSet.contains(addr)) {
			nextBlock = model.getCodeBlockAt(addr, monitor);
			if (nextBlock != null) {
				nextAddr = nextBlock.getMaxAddress();
				return;
			}
		}

		// otherwise we're out of our current address range in
		// our address range set so we find the next address range
		// with a min address >= the instructions address and
		// look for a block there
		//nextAddr = instr.getMaxAddress();
		while (rangeIter.hasNext()) {
			AddressRange range = rangeIter.next();

			if (nextAddr.compareTo(range.getMinAddress()) >= 0) {
				continue;
			}

			nextBlock = getFirstInRange(range);
			// if we find a block we're done
			if (nextBlock != null) {
				nextAddr = nextBlock.getMaxAddress();
				return;
			}
			// if we find no block then there's no block in the
			// current range and we can move on to the next one
		}
		nextBlock = null;
	}

	/**
	 * Find the next Address that starts a valid block
	 */
	private Address getNextAddress(Address addr) {

		Instruction instr = listing.getInstructionAfter(addr);
		Address instrAddr = instr != null ? instr.getMinAddress() : null;

		return instrAddr;
// ?? ITERATOR HAS BEEN MODIFIED TO ONLY RETURN INSTRUCTION BLOCKS

//        Data data = getDefinedDataAfter(addr);
//        Address dataAddr = data != null ? data.getMinAddress() : null;
//        
//        if (instrAddr != null) {
//        	if (dataAddr != null) {
//        		return (instrAddr.compareTo(dataAddr) < 0) ? instrAddr : dataAddr;
//        	}
//        	else {
//        		return instrAddr;
//        	}
//        }
//        return dataAddr;
	}

//    /**
//     * Get the next defined data object from the listing which occurs after the nextAddr.
//     * The cached data in nextData is used so that we only search over an area of code one time.
//     * @param nextAddr searching will begin immediately following this address.
//     * @return the next defined data found after nextAddr, or null if none found.
//     */
//    private Data getDefinedDataAfter(Address addr) {
//    	if (noMoreData)
//    		return null;
//    	Data data = null;
//    	if (nextData != null && addr.compareTo(nextData.getMinAddress()) < 0) {
//    		data = nextData;
//    		nextData = null;
//    		return data;
//    	}
//    	do {
//    		data = listing.getDefinedDataAfter(addr);
//    		if (data == null)
//    			break;
//    		if (dataReferencesInstruction(data)) {
//    			nextData = data;
//				return data;
//    		}
//    		addr = data.getMaxAddress();
//    	} while (addr != null);
//    	noMoreData = true;
//    	return null;
//    }
//    
//    private Data nextData = null; // used to remember last data returned
//    private boolean noMoreData = false;
//    
//    /**
//     * Determine if the specified data object contains a code reference.
//     * @param data a data object.
//     * @return true if data has a code reference (example: data is a pointer to code).
//     */
//    private boolean dataReferencesInstruction(Data data) {
//    	
//		MemReference[] refs = data.getReferencesFrom();
//		for (int i = 0; i < refs.length; i++) {
//			Instruction instr = listing.getInstructionContaining(refs[i].getToAddress());
//			if (instr != null) {
//				return true;
//			}
//		}	
//    	return false;
//    }

	/**
	 * Finds the first block occurring in the given range.
	 * @param range  the range to look for the block in.
	 * @return will return null if no code block can be found.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	private CodeBlock getFirstInRange(AddressRange range) throws CancelledException {
		Address addr = range.getMinAddress();
		if (addr == null) {
			return null;
		}
		do {
			CodeBlock block = model.getFirstCodeBlockContaining(addr, monitor);
			if (block != null) {
				CodeUnit codeUnit = listing.getCodeUnitAt(block.getMinAddress());
				if (codeUnit instanceof Instruction)
					return block;
// ?? ITERATOR HAS BEEN MODIFIED TO ONLY RETURN INSTRUCTION BLOCKS

//		    	if (codeUnit instanceof Data) {
//		    		// Only data blocks which reference an instruction are valid
//		    		if (dataReferencesInstruction((Data)codeUnit)) {
//		    			return block;
//		    		}
//		    	}
//		    	else {
//		    		// Instruction block is always valid
//		    		return block;	
//		    	}
				addr = block.getMaxAddress();
			}
			addr = getNextAddress(addr);
		}
		while (!monitor.isCancelled() && addr != null && range.contains(addr));    // while still in range

		return null;
	}

}

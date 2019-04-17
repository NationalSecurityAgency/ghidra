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
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <CODE>MultEntSubIterator</CODE> is an implementation of
 * <CODE>CodeBlockIterator</CODE> capable of iterating in
 * the forward direction over subroutine code blocks.
 * The iterator supports subroutine models which allow one or
 * more called/source entry points within a subroutine and do not
 * share code with other subroutines produced by the same model.
 */
class MultEntSubIterator implements CodeBlockIterator {

	private Listing listing = null;

	// The next subroutine block to be returned
	private CodeBlock nextSub = null;

	// Addresses to iterate over
	private AddressSet addrSet = null;

	private MultEntSubModel model = null;
	private TaskMonitor monitor;

	/**
	 * Creates a new iterator that will iterate over the entire
	 * program starting from its current minimum address.
	 *
	 * @param model  the BlockModel the iterator will use in its operations.
	 * @param monitor task monitor which allows user to cancel operation.
	 */
	MultEntSubIterator(MultEntSubModel model, TaskMonitor monitor) {
		this.model = model;
		this.monitor = monitor != null ? monitor : TaskMonitor.DUMMY;
		listing = model.getProgram().getListing();
		addrSet = new AddressSet(model.getProgram().getMemory());
		nextSub = null;
	}

	/**
	 * Creates a new iterator that will iterate over the
	 * program within a given address range set. All blocks which 
	 * overlap the address set will be returned.
	 * <P>
	 *
	 * @param model  the SubroutineModel the iterator will use in its operations.
	 * @param set    the address range set which the iterator is to be
	 *               restricted to.
	 * @param monitor task monitor which allows user to cancel operation.
	 */
	MultEntSubIterator(MultEntSubModel model, AddressSetView set, TaskMonitor monitor) {
		this.model = model;
		this.monitor = monitor;
		monitor.setIndeterminate(true);
		listing = model.getProgram().getListing();
		addrSet = new AddressSet(set);
		nextSub = null;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockIterator#hasNext()
	 */
	@Override
	public boolean hasNext() throws CancelledException {
		if (nextSub != null) {
			return true;
		}

		Address addr = addrSet.getMinAddress();
		if (addr == null) {
			return false;
		}

		if (addr.isExternalAddress()) {
			nextSub = model.getCodeBlockAt(addr, monitor);
			addrSet.deleteRange(addr, addr);
			return true;
		}

		Instruction instr = listing.getInstructionAt(addr);
		if (instr == null) {
			addrSet.deleteRange(addr, addr);
		}

		while (instr == null) {

			if (monitor != null && monitor.isCancelled())
				throw new CancelledException();

			instr = listing.getInstructionAfter(addr);

			// If no more instructions we are done
			if (instr == null) {
				addrSet.clear();
				return false;
			}

			// Clear skipped addresses 
			Address minAddr = instr.getMinAddress();
			boolean setHadMinAddr = addrSet.contains(minAddr);
			addrSet.deleteRange(addr, minAddr);
			if (setHadMinAddr) {
				addrSet.addRange(minAddr, minAddr);
			}

			addr = minAddr;

			// If this instruction not in current set, repeat loop
			if (!addrSet.contains(addr)) {
				instr = null;
				addr = addrSet.getMinAddress();
				if (addr == null) {
					return false;
				}
			}
		}

		// Get code block which contains instruction address
		nextSub = model.getFirstCodeBlockContaining(addr, monitor);
		addrSet.delete(nextSub);
		return true;
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockIterator#next()
	 */
	@Override
	public CodeBlock next() throws CancelledException {
		if (nextSub == null) {
			hasNext();
		}
		CodeBlock retSub = nextSub;
		nextSub = null;
		return retSub;
	}
}

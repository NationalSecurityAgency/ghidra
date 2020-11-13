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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.LinkedList;

/**
 * <CODE>SingleEntSubIterator</CODE> is an implementation of
 * <CODE>CodeBlockIterator</CODE> capable of iterating in
 * the forward direction over subroutine code blocks.
 * This iterator supports subroutine models which allow only one
 * called/source entry point within a subroutine and may
 * share code with other subroutines produced by the same model.
 * All entry points must be accounted for within M-Model subroutines.
 *
 * NOTE: This iterator only supports OverlapCodeSubModel block models
 * and extensions.
 *
 * NOTE: If the containing M-model subroutine has two entry points, say
 * A and B, such that the code traversed from A is identical to the code traversed
 * by B (due to a cycle), then this iterator will include it twice rather than
 * skipping over the identical address set.  This is because the iterator works by
 * iterating through M-model subroutines, and wherever M-model subroutines have
 * n &gt; 1 multiple entry points, the iterator produces an O-model subroutine
 * for every one of the entry points.
 */
public class SingleEntSubIterator implements CodeBlockIterator {

	// at any given time nextSub will either be null or hold the
	// next block to be returned by next()
	private CodeBlock nextSub = null;

	// address range set specified for iterator
	private AddressSetView addrSet = null;

	private OverlapCodeSubModel model = null;

	// create holder for model-P subs that came from model-M subs with multiple entry points
	private LinkedList<CodeBlock> subList = new LinkedList<CodeBlock>();

	private CodeBlockIterator modelMIter = null;
	private TaskMonitor monitor;

	/**
	 * Creates a new iterator that will iterate over the entire
	 * program starting from its current minimum address.
	 * @param model  the BlockModel the iterator will use in its operations.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	public SingleEntSubIterator(OverlapCodeSubModel model, TaskMonitor monitor)
			throws CancelledException {
		this.model = model;
		this.monitor = monitor != null ? monitor : TaskMonitor.DUMMY;
		addrSet = null;
		nextSub = null;
		modelMIter = model.getModelM().getCodeBlocks(monitor);
	}

	/**
	 * Creates a new iterator that will iterate over the
	 * program within a given address range set. All blocks which 
	 * overlap the address set will be returned.
	 * <P>
	 * @param model  the BlockModel the iterator will use in its operations.
	 * @param set    the address range set which the iterator is to be
	 *               restricted to.
	 * @param monitor task monitor which allows user to cancel operation.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	public SingleEntSubIterator(OverlapCodeSubModel model, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		this.model = model;
		this.monitor = monitor;
		monitor.setIndeterminate(true);
		addrSet = set;
		nextSub = null;
		modelMIter = model.getModelM().getCodeBlocksContaining(set, monitor);
	}

	/**
	 * @see ghidra.program.model.block.CodeBlockIterator#hasNext()
	 */
	@Override
	public boolean hasNext() throws CancelledException {

		if (nextSub != null) {
			return true;
		}

		if (!subList.isEmpty()) {
			nextSub = subList.removeFirst();
			return true;
		}

		// Iterate over each Model-M subroutine
		if (modelMIter.hasNext()) {

			CodeBlock modelMSub = modelMIter.next();
			Address[] entPts = modelMSub.getStartAddresses();

			// Check all Model-O subroutines contained within the Model-M subroutine
			for (int i = 0; i < entPts.length; i++) {

				CodeBlock sub = model.getCodeBlockAt(entPts[i], monitor);
				if (sub == null)
					continue;   // should only happen with screwy code

				if (monitor.isCancelled())
					return false;

				if (addrSet != null) {

					// Keep sub only if it overlaps address set
					if (!sub.intersects(addrSet)) {
						continue;
					}
				}
				subList.add(sub);
			}

			// Check for available subroutine which may have been added to list
			if (!subList.isEmpty()) {
				nextSub = subList.removeFirst();
				return true;
			}
		}
		return false;
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

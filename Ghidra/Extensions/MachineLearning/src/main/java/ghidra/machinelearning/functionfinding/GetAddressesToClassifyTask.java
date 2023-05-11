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
package ghidra.machinelearning.functionfinding;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Task} for gathering addresses to feed to a function start classifier
 */

public class GetAddressesToClassifyTask extends Task {
	private Program prog;
	private AddressSet execNonFunc;
	private long minUndefinedRangeSize;

	/**
	 * Creates a {@link Task} that creates a set of addresses to check for function starts.  The
	 * {code minUndefinedRangeSize} parameter determines how large a run of undefined bytes must be
	 * to be checked for function starts
	 * @param prog source program
	 * @param minUndefinedRangeSize minimum size of undefined range
	 */
	public GetAddressesToClassifyTask(Program prog, long minUndefinedRangeSize) {
		super("Gathering Addresses to Classify", true, true, false, false);
		this.prog = prog;
		this.minUndefinedRangeSize = minUndefinedRangeSize;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		execNonFunc = new AddressSet();
		AddressSetView executable = prog.getMemory().getExecuteSet();
		AddressSetView initialized = prog.getMemory().getLoadedAndInitializedAddressSet();
		execNonFunc = executable.intersect(initialized);
		monitor.initialize(prog.getFunctionManager().getFunctionCount());
		FunctionIterator fIter = prog.getFunctionManager().getFunctions(true);
		while (fIter.hasNext()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			Function func = fIter.next();
			execNonFunc = execNonFunc.subtract(func.getBody());
		}
		//remove small undefined ranges to avoid (for example) searching for
		//function starts in an address range of length 3 between two known
		//functions.  "small" is controlled by a plugin option.
		AddressSetView undefinedRanges =
			prog.getListing().getUndefinedRanges(execNonFunc, true, monitor);
		AddressSet toRemove = new AddressSet();
		AddressRangeIterator iter = undefinedRanges.getAddressRanges(true);
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			if (range.getLength() <= minUndefinedRangeSize) {
				toRemove.add(range);
			}
		}
		execNonFunc = execNonFunc.subtract(toRemove);
	}

	/**
	 * Returns the set of addresses to classify
	 * @return addresses
	 */
	public AddressSet getAddressesToClassify() {
		return execNonFunc;
	}

	/**
	 * Returns the subsets of the addresses to classify consisting of all addresses
	 * which are aligned relative to the given modulus.
	 * @param modulus alignment modulus
	 * @return aligned addresses
	 */
	public AddressSet getAddressesToClassify(long modulus) {
		AddressSet aligned = new AddressSet();
		for (Address a : execNonFunc.getAddresses(true)) {
			if (a.getOffset() % modulus == 0) {
				aligned.add(a);
			}
		}
		return aligned;
	}

}

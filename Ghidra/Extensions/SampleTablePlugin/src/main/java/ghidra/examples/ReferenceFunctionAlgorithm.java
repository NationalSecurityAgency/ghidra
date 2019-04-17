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
package ghidra.examples;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ReferenceFunctionAlgorithm implements FunctionAlgorithm {

	@Override
	public String getName() {
		return "Reference Counter";
	}

	@Override
	public int score(Function function, TaskMonitor monitor) throws CancelledException {
		Program program = function.getProgram();
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressSetView body = function.getBody();
		long maxIterations = body.getNumAddresses();
		monitor.initialize(maxIterations);

		AddressIterator iterator = referenceManager.getReferenceSourceIterator(body, true);
		int referenceCount = 0;
		while (iterator.hasNext()) {
			monitor.checkCanceled();
			Address address = iterator.next();
			Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
			referenceCount += referencesFrom.length;
			monitor.incrementProgress(1);

			artificialSleepForDemoPurposes();
		}
		return referenceCount;
	}

	private void artificialSleepForDemoPurposes() {
		try {
			Thread.sleep(10);
		}
		catch (InterruptedException e) {
			// don't care; we tried
		}
	}
}

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
//Iterates over all functions in the current program
//starting at the minimum address of the program.
//
//@category Iteration

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class IterateFunctionsByAddressScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		boolean forward =
			askYesNo("Iterate Function", "Do you want to iterate from low address to high address?");

		if (forward) {
			iterateForward();
		}
		else {
			iterateBackward();
		}
	}

	private void iterateForward() {
		// Use the iterator, there is no easy way to use the function iterator on addresses
		//   If the function begins at address zero, you won't get the function without
		//   alot of extra more complicated code.
		FunctionIterator fiter = currentProgram.getFunctionManager().getFunctions(true);

		int count = 0;
		while (fiter.hasNext()) {
			Function function = fiter.next();

			if (monitor.isCancelled()) {
				break;
			}

			String string = count + "  :  " + function.getName() + " @ " + function.getEntryPoint();

			monitor.setMessage(string);

			println(string);

			count++;
		}
		println("found " + count + " functions ");
	}

	private void iterateBackward() {
		Address minAddress = currentProgram.getMinAddress();

		Address address = currentProgram.getMaxAddress();

		int count = 0;
		while (address.compareTo(minAddress) >= 0) {

			if (monitor.isCancelled()) {
				break;
			}

			Function function = getFunctionBefore(address);

			if (function == null) {
				break;
			}

			String string = count + "  :  " + function.getName() + " @ " + function.getEntryPoint();

			monitor.setMessage(string);

			println(string);

			address = function.getEntryPoint();

			count++;
		}
		println("found " + count + " functions ");
	}
}

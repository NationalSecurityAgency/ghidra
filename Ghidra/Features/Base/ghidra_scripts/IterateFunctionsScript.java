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
//Iterates over all functions in the current program.
//@category Iteration

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class IterateFunctionsScript extends GhidraScript {

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

		Function function = getFirstFunction();

		int count = 0;
		while (true) {

			if (monitor.isCancelled()) {
				break;
			}

			if (function == null) {
				break;
			}

			String string = count + "  :  " + function.getName() + " @ " + function.getEntryPoint();

			monitor.setMessage(string);

			println(string);

			function = getFunctionAfter(function);
			count++;
		}
		println("found forward = " + count);
	}

	private void iterateBackward() {

		Function function = getLastFunction();

		int count = 0;
		while (true) {

			if (monitor.isCancelled()) {
				break;
			}

			if (function == null) {
				break;
			}

			String string = count + "  :  " + function.getName() + " @ " + function.getEntryPoint();

			monitor.setMessage(string);

			println(string);

			function = getFunctionBefore(function);

			count++;
		}
		println("found forward = " + count);
	}

}

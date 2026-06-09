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
// An example script that will print to the console, for a given function, all other functions
// that call it and all functions that it calls.
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class PrintFunctionCallTreesScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		Function function = getCurrentFunction();
		if (function == null) {
			println("Cursor is not in or on a function");
			return;
		}

		printIncomingCalls(function);
		println("\n");
		printOutgoingCalls(function);
	}

	private void printIncomingCalls(Function function) {

		Set<Function> callingFunctions = function.getCallingFunctions(monitor);

		// sort them by address
		List<Function> list = new ArrayList<>(callingFunctions);
		Collections.sort(list, (f1, f2) -> f1.getEntryPoint().compareTo(f2.getEntryPoint()));

		for (Function f : list) {
			println("Incoming Function Call: " + f.getName() + " @ " + f.getEntryPoint());
		}
	}

	private void printOutgoingCalls(Function function) {

		Set<Function> outgoingFunctions = function.getCalledFunctions(monitor);

		// sort them by address
		List<Function> list = new ArrayList<>(outgoingFunctions);
		Collections.sort(list, (f1, f2) -> f1.getEntryPoint().compareTo(f2.getEntryPoint()));

		for (Function f : list) {
			println("Outgoing Function Call: " + f.getName() + " @ " + f.getEntryPoint());
		}
	}

	private Function getCurrentFunction() {
		FunctionManager functionManager = currentProgram.getFunctionManager();
		return functionManager.getFunctionContaining(currentAddress);
	}

}

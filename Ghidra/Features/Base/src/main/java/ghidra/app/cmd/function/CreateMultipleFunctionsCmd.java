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
package ghidra.app.cmd.function;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Command for Creating multiple functions from a selection.
 * This tries to create functions by working from the minimum address to the maximum address in
 * the selection. Any addresses in the selection that are already in existing functions are
 * discarded. Every time a function is created, all the other addresses for that function are
 * also discarded.
 *
 */
public class CreateMultipleFunctionsCmd extends BackgroundCommand<Program> {

	private AddressSetView selection;
	private SourceType source;

	public CreateMultipleFunctionsCmd(AddressSetView selection, SourceType source) {
		super("Create Multiple Functions", true, true, false);
		this.selection = selection;
		this.source = source;
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor monitor) {

		Listing listing = program.getListing();
		AddressSet addressSet = new AddressSet(selection);
		Address address = addressSet.getMinAddress();
		int functionsCreated = 0;
		long numInitialAddresses = addressSet.getNumAddresses();
		monitor.initialize(numInitialAddresses);
		monitor.setMessage("Creating functions from selection.");

		while (address != null && !monitor.isCancelled()) {
			// Try to get a function containing the current address.
			Function function = listing.getFunctionContaining(address);
			if (function == null) {
				// Create the next function.
				CreateFunctionCmd createFunctionCmd =
					new CreateFunctionCmd(null, address, null, source);
				if (createFunctionCmd.applyTo(program, monitor)) {
					function = createFunctionCmd.getFunction();
					functionsCreated++;
				}
			}

			if (function != null) {
				AddressSetView body = function.getBody();
				addressSet.delete(body);
			}
			addressSet.deleteRange(address, address);
			address = addressSet.getMinAddress();
			long numRemainingAddresses = addressSet.getNumAddresses();
			monitor.setProgress(numInitialAddresses - numRemainingAddresses);
		}
		if (monitor.isCancelled()) {
			Msg.info(this, "User canceled " + getName() + ".");
			return false;
		}
		Msg.info(this, functionsCreated + " functions created by " + getName() + ".");
		return true;
	}

}

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
// Finds instructions that are not inside a defined function body
// and locates the start of each instruction flow.
//
// In headless mode displays a count of the potential function starts.
// In headed mode displays a table identifying the start locations of all
// unreferenced code.
//
// @category Search

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class FindInstructionsNotInsideFunctionScript extends GhidraScript {

	/**
	 * @see ghidra.app.script.GhidraScript#run()
	 */
	@Override
	public void run() throws Exception {
		AddressSet set = new AddressSet();
		Listing listing = currentProgram.getListing();

		InstructionIterator initer = listing.getInstructions(currentProgram.getMemory(), true);
		while (initer.hasNext() && !monitor.isCancelled()) {
			Instruction instruct = initer.next();
			set.addRange(instruct.getMinAddress(), instruct.getMaxAddress());
		}
		FunctionIterator iter = listing.getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function f = iter.next();
			set.delete(f.getBody());
		}

		if (set.getNumAddressRanges() == 0) {
			popup("NO RESULTS - all instructions are contained inside functions");
			return;
		}

		//
		// go through address set and find the actual start of flow into the dead code
		//
		IsolatedEntrySubModel submodel = new IsolatedEntrySubModel(currentProgram);
		CodeBlockIterator subIter = submodel.getCodeBlocksContaining(set, monitor);
		AddressSet codeStarts = new AddressSet();
		while (subIter.hasNext()) {
			CodeBlock block = subIter.next();
			Address deadStart = block.getFirstStartAddress();
			codeStarts.add(deadStart);
		}

		if (SystemUtilities.isInHeadlessMode()) {
			Msg.error(this, "POSSIBLE UNDEFINED FUNCTIONS: # " + codeStarts.getNumAddresses());
		}
		else {
			show("Possible Undefined functions", codeStarts);
		}
	}

}

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
//This script propagates constants in a function creating references wherever a store or load is
//found.  If a register has a value at the beginning of a function, that register value is assumed
//to be a constant.
//Any values loaded from memory are assumed to be constant.
//If a reference does not make sense on an operand, then it is added to the mnemonic.
//
//@category Analysis

import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.SymbolicPropogator;

public class PropagateConstantReferences extends GhidraScript {

	@Override
	public void run() throws Exception {
		long numInstructions = currentProgram.getListing().getNumInstructions();
		monitor.initialize((int) (numInstructions));
		monitor.setMessage("Constant Propagation Markup");

		// set up the address set to restrict processing
		AddressSet restrictedSet =
			new AddressSet(currentSelection);
		if (restrictedSet.isEmpty()) {
			Function curFunc =
				currentProgram.getFunctionManager().getFunctionContaining(
					currentLocation.getAddress());
			if (curFunc != null) {
				restrictedSet =
					new AddressSet(curFunc.getEntryPoint());
			}
			else {
				restrictedSet =
					new AddressSet(currentLocation.getAddress());
			}

		}

		// iterate over all functions within the restricted set
		FunctionIterator fiter =
			currentProgram.getFunctionManager().getFunctions(restrictedSet, true);
		while (fiter.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			// get the function body
			Function func = fiter.next();
			Address start = func.getEntryPoint();

			// follow all flows building up context
			// use context to fill out addresses on certain instructions 
			ContextEvaluator eval = new ConstantPropagationContextEvaluator(true);

			SymbolicPropogator symEval = new SymbolicPropogator(currentProgram);

			symEval.flowConstants(start, func.getBody(), eval, true, monitor);
		}
	}

}

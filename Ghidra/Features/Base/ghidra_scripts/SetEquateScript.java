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
//This script asks for a name and value for an equate and applies it at all scalar operands 
// in the current selection (if applicable) or the entire program if no selection is made
//@author
//@category 
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;

public class SetEquateScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		// Get listing for current program
		Listing listing = currentProgram.getListing();

		// bools to be able to inform user if scalar values were found
		boolean scalarFound = false;
		boolean userScalarFound = false;

		// Prompt user to input scalar value to search for
		Integer scalarValue =
			askInt("Scalar value", "Please input the scalar value you want to search for");

		// Prompt user to input the name for the equate
		String equateName =
			askString("Equate name", "Please input the name of the equate you wish to add");
		// TODO: check to see if the equate name already exists

		// Iterator declarations
		InstructionIterator iter;

		// Check to see if there is a selection
		if (currentSelection != null) {
			// Create iterator to check current selection
			iter = listing.getInstructions(currentSelection, true);
		}
		else {
			// Create iterator to check whole program
			iter = listing.getInstructions(currentProgram.getMemory(), true);
		}

		// checks if there is a next value and if the user has canceled the
		// request
		while (iter.hasNext() && !monitor.isCancelled()) {
			// Grabs next value
			Instruction tempValue = iter.next();

			// Find out how many operands are listed
			int numOperands = tempValue.getNumOperands();

			for (int i = 0; i <= numOperands; i++) {
				// Checks to see if the current value is a scalar value
				if (tempValue.getOperandType(i) == (OperandType.SCALAR)) {

					scalarFound = true; // a scalar value was found

					// Checks to see if the scalar value is equal to the value
					// we are searching for
					if (tempValue.getScalar(i).getUnsignedValue() == scalarValue) {

						userScalarFound = true; // the scalar value the user was
												// looking for was found

						// Sets the equate to the user defined name and execute
						Command cmd =
							new SetEquateCmd(equateName, tempValue.getAddress(), i, scalarValue);
						state.getTool().execute(cmd, currentProgram);

						// print out the new information for user
						println("A new equate named " + equateName +
							" has been set for the scalar value " + scalarValue + " at address " +
							tempValue.getAddress() + " and at operand " + i);
					}
				}
			}
		}
		// checks to see if the scalar value was found and informs user
		if (scalarFound == false && userScalarFound == false) {
			println("No scalar values were found.");
		}
		else if (scalarFound == true && userScalarFound == false) {
			println("No " + scalarValue + " values were found");
		}
	}
}

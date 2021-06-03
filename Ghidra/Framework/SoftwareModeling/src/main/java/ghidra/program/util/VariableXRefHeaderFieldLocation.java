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
package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;

public class VariableXRefHeaderFieldLocation extends VariableXRefFieldLocation {

	/**
	 * Should only be used for XML restoring.
	 */
	public VariableXRefHeaderFieldLocation() {
		super();
	}

	/**
	 * Creates a variable xref field program location
	 * @param program the program of the location
	 * @param var the variable
	 * @param charOffset the character offset
	 * @param refAddr the xref address
	 */
	public VariableXRefHeaderFieldLocation(Program program, Variable var, int charOffset,
			Address refAddr) {
		// not sure if -1 breaks anything, but a header location does not really have an order
		// in the function
		super(program, var, refAddr, 0, charOffset);
	}

}

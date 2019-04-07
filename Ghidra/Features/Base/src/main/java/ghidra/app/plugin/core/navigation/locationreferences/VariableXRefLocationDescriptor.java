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
package ghidra.app.plugin.core.navigation.locationreferences;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableXRefFieldLocation;
import ghidra.util.exception.AssertException;

public class VariableXRefLocationDescriptor extends XRefLocationDescriptor {

	VariableXRefLocationDescriptor(ProgramLocation location, Program program) {
		super(location, program);
	}

	@Override
	protected void validate() {
		if (programLocation == null) {
			throw new NullPointerException(
				"Cannot create a LocationDescriptor from a null " + "ProgramLocation");
		}

		if (!(programLocation instanceof VariableXRefFieldLocation)) {
			throw new AssertException("Unexpected ProgramLocation type - Cannot create a " +
				"LocationDescriptor for type: " + programLocation);
		}
	}

	@Override
	protected Address getXRefAddress(ProgramLocation location) {
		return ((VariableXRefFieldLocation) location).getRefAddress();
	}
}

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

import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.util.*;
import ghidra.util.exception.AssertException;

class VariableNameLocationDescriptor extends FunctionParameterNameLocationDescriptor {

	private OperandFieldLocation alternateHomeLocation;

	VariableNameLocationDescriptor(VariableNameFieldLocation location, Program program) {
		super(location, program);
		Variable variable = getVariable();
		if (variable != null) {
			homeAddress = variable.getMinAddress();
		}
		else {
			homeAddress = location.getAddress();
		}
	}

	/**
	 * Note: this is the same as {@link #VariableNameLocationDescriptor(ProgramLocation, Program)}
	 * except that it allows you to specify an alternate home location.  This is useful for
	 * finding references to function variable names from operand fields.
	 */
	VariableNameLocationDescriptor(VariableNameFieldLocation location,
			OperandFieldLocation alternateHomeLocation, Program program) {
		super(location, program);
		this.alternateHomeLocation = alternateHomeLocation;
		homeAddress = alternateHomeLocation.getAddress();

	}

	@Override
	protected void validate(FunctionLocation location) {
		if (location == null) {
			throw new NullPointerException(
				"Cannot create a LocationDescriptor from a null ProgramLocation");
		}

		if (!(programLocation instanceof VariableNameFieldLocation)) {
			throw new AssertException("Unexpected ProgramLocation type - Cannot create a " +
				"LocationDescriptor for type: " + programLocation);
		}
	}

	@Override
	// overridden to use our potential alternate home address
	ProgramLocation getHomeLocation() {
		if (alternateHomeLocation != null) {
			return alternateHomeLocation;
		}
		return super.getHomeLocation();
	}

	@Override
	protected Variable getVariable() {
		return ((VariableNameFieldLocation) programLocation).getVariable();
	}

	@Override
	protected String getVariableName() {
		return ((VariableNameFieldLocation) programLocation).getName();
	}
}

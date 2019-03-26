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
package ghidra.util.constraint;

import generic.constraint.ConstraintData;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;

public class PropertyConstraint extends ProgramConstraint {

	public PropertyConstraint() {
		super("property");
	}

	private String name;				// name of the program property to constrain
	private String value;			// value the property should take

	@Override
	public boolean isSatisfied(Program program) {
		String val = program.getOptions(Program.PROGRAM_INFO).getValueAsString(name);
		return SystemUtilities.isEqual(val, value);
	}

	@Override
	public void loadConstraintData(ConstraintData data) {
		name = data.getString("name");
		value = data.getString("value");
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof PropertyConstraint)) {
			return false;
		}
		PropertyConstraint other = (PropertyConstraint) obj;
		return other.name.equals(name) && other.value.equals(value);
	}

	@Override
	public String getDescription() {
		return "property " + name + " = " + value;
	}

}

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
package ghidra.app.extension.datatype.finder;

import java.util.List;

import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext;
import ghidra.app.services.DataTypeReference;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.AssertException;

/**
 * Represents a type declaration and variable pair.
 */
public abstract class VariableDR extends DecompilerReference {

	protected DecompilerVariable declaration;

	protected VariableDR(ClangLine line, ClangTypeToken type) {
		super(line, type);

		declaration = new DecompilerVariableType(type);
	}

	void setVariable(ClangVariableToken token) {
		variable = new DecompilerVariableType(token);
	}

	public DecompilerVariable getDeclaration() {
		return declaration;
	}

	@Override
	public DecompilerVariable getVariable() {
		return variable;
	}

	@Override
	public void accumulateMatches(DataType dt, String fieldName, List<DataTypeReference> results) {

		if (variable == null) {
			// This implies our API was misused in that a variable was never set after creation
			throw new AssertException("Decompiler variable declaration is missing a name");
		}

		DataType dataType = getDataType();
		if (!isEqual(dataType, dt)) {
			// wrong type, nothing to do
			return;
		}

		LocationReferenceContext context = getContext();
		Function function = getFunction();
		Address address = getAddress();
		if (fieldName == null) {
			// no field to check, a match on the the type is good enough
			results.add(new DataTypeReference(dataType, null, getFunction(), address, context));
			return;
		}

		String name = variable.getName();
		if (name.equals(fieldName)) {
			results.add(new DataTypeReference(dataType, fieldName, function, address, context));
		}
	}
}

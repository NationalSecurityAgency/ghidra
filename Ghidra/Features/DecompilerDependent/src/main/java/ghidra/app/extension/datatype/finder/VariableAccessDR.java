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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.*;
import ghidra.app.services.DataTypeReference;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.StringUtilities;
import ghidra.util.exception.AssertException;

/**
 * A class that describes Decompiler variables and the fields that they may access.
 */
public class VariableAccessDR extends DecompilerReference {

	private List<DecompilerFieldAccess> fields = new ArrayList<>();

	protected VariableAccessDR(ClangLine line) {
		super(line, null /* This class does not always have a 'type' token */);
	}

	protected VariableAccessDR(ClangLine line, ClangFieldToken token) {
		super(line, token);
	}

	void setVariable(ClangVariableToken token, List<DecompilerVariable> casts) {
		if (variable != null) {
			throw new AssertException("Decompiler variable is already set for this access");
		}

		variable = new DecompilerVariableType(token, casts);
	}

	void addField(ClangFieldToken token, List<DecompilerVariable> fieldCasts) {
		DecompilerFieldAccess field = new DecompilerFieldAccess(token, fieldCasts);
		fields.add(field);
	}

	@Override
	public void accumulateMatches(DataType dt, String fieldName, List<DataTypeReference> results) {

		if (fields.isEmpty()) {
			DecompilerVariable var = getMatch(dt, fieldName, variable, null);
			if (var != null) {
				DataTypeReference ref = createReference(var);
				results.add(ref);
			}
			return;
		}

		//
		// Walk each pair of type and variables in order to see if any of them match our 
		// criteria
		//
		DecompilerVariable start = variable;
		for (DecompilerVariable field : fields) {

			DecompilerVariable next = field;
			DecompilerVariable var = getMatch(dt, fieldName, start, next);
			if (var != null) {
				DataTypeReference ref = createReference(var, next);
				results.add(ref);
			}

			start = next;
		}

		//
		// Handle the last variable by itself (for the case where we are matching just on the
		// type, with no field name)
		// 
		if (fieldName != null) {
			return;
		}

		DecompilerVariable var = getMatch(dt, null, start, null);
		if (var != null) {
			DataTypeReference ref = createReference(var);
			results.add(ref);
		}
	}

	private DecompilerVariable getMatch(DataType dt, String fieldName, DecompilerVariable var,
			DecompilerVariable potentialField) {

		// Note: for now, I ignore the precedence of casting; if any cast type is a match, then
		//       signal hooray
		boolean searchForField = fieldName != null;
		DecompilerVariable fieldVar = searchForField ? potentialField : null;
		DecompilerVariable match = getMatchingVarialbe(dt, var, fieldVar);
		if (match == null) {
			// wrong type, nothing to do
			return null;
		}

		// Matches on the type, does the field match?
		if (fieldName == null) {
			return match; // no field to match
		}

		if (potentialField == null) {
			return null; // we seek a field, but there is none
		}

		String name = potentialField.getName();
		if (fieldName.equals(name)) {
			return match;
		}
		return null;
	}

	private DecompilerVariable getMatchingVarialbe(DataType dt, DecompilerVariable var,
			DecompilerVariable potentialField) {

		List<DecompilerVariable> castVariables = var.getCasts();
		for (DecompilerVariable cast : castVariables) {
			if (matchesType(cast, dt)) {
				return cast;
			}
		}

		if (matchesType(var, dt)) {
			return var;
		}

		//
		// 						Unusual Code Alert!
		// It is a bit odd to check the field when you are looking for the type that contains
		// the field.  BUT, in the Decompiler, SOMETIMES the 'field' happens to have the 
		// data type of the thing that contains it.  So, if you have:
		// 		foo.bar
		// then the 'bar' field will have a data type of Foo.   Unfortunately, this is not 
		// always the case.  For now, when the variable is global, we need to check the field
		// Sad face emoji.
		//
		HighVariable highVariable = var.variable.getHighVariable();
		if (highVariable instanceof HighGlobal) {
			if (matchesParentType(potentialField, dt)) {
				return potentialField;
			}
		}

		return null;
	}

	private boolean matchesParentType(DecompilerVariable var, DataType dt) {
		if (var == null) {
			return false;
		}

		DataType varType = var.getParentDataType();
		boolean matches = isEqual(varType, dt);
		return matches;
	}

	private boolean matchesType(DecompilerVariable var, DataType dt) {
		if (var == null) {
			return false;
		}

		DataType varType = var.getDataType();
		if (varType == null) {
			// it seems odd to me that there is no type, but I have seen this in the case
			// statement of a switch
			return false;
		}
		boolean matches = isEqual(varType, dt);
		return matches;
	}

	protected DataTypeReference createReference(DecompilerVariable var) {

		DataType dataType = var.getDataType();
		String context = getContext(var);
		Function function = var.getFunction();
		Address address = getAddress(var);
		return new DataTypeReference(dataType, null, function, address, context);
	}

	private DataTypeReference createReference(DecompilerVariable var, DecompilerVariable field) {
		DataType dataType = var.getDataType();
		String context = getContext(var);
		Function function = var.getFunction();
		Address address = getAddress(var);
		return new DataTypeReference(dataType, field.getName(), function, address, context);
	}

	@Override
	protected String getContext(DecompilerVariable var) {
		DecompilerVariable field = findFieldFor(var);
		String context = super.getContext(field);
		return context;
	}

	private DecompilerVariable findFieldFor(DecompilerVariable var) {

		// 
		// 			Unusual Code Alert!
		//
		// The fact that we need to locate the given variable is a bit odd. But, elsewhere in
		// this file we figured out which variable (out of the casts, the variable and the 
		// accesses) is the type we seek.  So, now we have a variable, but we don't know
		// if it is the field or if one of the accesses is the field.  So, this method walks
		// all variables in order to find the given variable, then returns the next variable, as
		// this represents the field in which we are interested.
		//

		List<DecompilerVariable> allVars = getAllVariablesInOrder();

		int varIndex = allVars.indexOf(var);
		if (varIndex == -1) {
			// this shouldn't happen; die gracefully, just in case
			throw new AssertException("Cannot find a field for variable " + var);
		}

		// assume 'var' is the parent of the field we seek (it may actually be the field itself)
		int fieldIndex = varIndex + 1;
		if (fieldIndex == allVars.size()) {
			// ...it must be the variable and the field
			fieldIndex = allVars.size() - 1;
		}

		DecompilerVariable field = allVars.get(fieldIndex);
		return field;
	}

	private List<DecompilerVariable> getAllVariablesInOrder() {
		List<DecompilerVariable> allVars = new ArrayList<>();
		getAllVariableTypes(variable, allVars);
		for (DecompilerVariable field : fields) {
			getAllVariableTypes(field, allVars);
		}

		return allVars;
	}

	private void getAllVariableTypes(DecompilerVariable var, List<DecompilerVariable> result) {
		List<DecompilerVariable> casts = var.getCasts();
		result.addAll(casts);
		result.add(var);
	}

	@Override
	public String toString() {
		String subFieldsString = fields.isEmpty() ? ""
				: "\tsub fields: " + StringUtilities.toStringWithIndent(fields) + ",\n";

		//@formatter:off
		return "{\n" +
			"\tline " + getContext() + ",\n" +
			"\tfunction: " + getFunction() + "\n" +
			"\tvariable: " + StringUtilities.toStringWithIndent(variable) + ",\n" +
			"\tdata type: " + getDataType() + ",\n"+ 
			subFieldsString +
		"}";
		//@formatter:on
	}
}

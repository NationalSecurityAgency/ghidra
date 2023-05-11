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
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext;
import ghidra.app.services.DataTypeReference;
import ghidra.app.services.FieldMatcher;
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
	public void accumulateMatches(DataType dt, FieldMatcher fieldMatcher,
			List<DataTypeReference> results) {

		if (fields.isEmpty()) {
			DecompilerVariable var = getMatch(dt, fieldMatcher, variable, null);
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
			DecompilerVariable var = getMatch(dt, fieldMatcher, start, next);
			if (var != null) {
				DataTypeReference ref = createReference(var, next);
				results.add(ref);
			}

			start = next;
		}

		//
		// Handle the last variable by itself (for the case where we are matching just on the type,
		// with no field name)
		//
		if (fieldMatcher.isIgnored()) {
			return;
		}

		DecompilerVariable var = getMatch(dt, fieldMatcher, start, null);
		if (var != null) {
			DataTypeReference ref = createReference(var);
			results.add(ref);
		}
	}

	private DecompilerVariable getMatch(DataType dt, FieldMatcher fieldMatcher,
			DecompilerVariable var, DecompilerVariable potentialField) {

		String indent = "\t\t";

		// Note: for now, I ignore the precedence of casting; if any cast type is a match, then
		//       signal hooray
		boolean searchForField = !fieldMatcher.isIgnored();
		DecompilerVariable fieldVar = searchForField ? potentialField : null;
		DecompilerVariable match = getMatchingVarialbe(dt, var, fieldVar);
		if (match == null) {
			DtrfDbg.println(this, indent + "NO MATCHING VARIABLE");
			return null; // wrong type, nothing to do
		}

		// Matches on the type, does the field match?
		if (fieldMatcher.isIgnored()) {
			DtrfDbg.println(this, indent + "field macher is ignored; returning match");
			return match; // no field to match
		}

		if (potentialField == null) {

			DtrfDbg.println(this, indent + "No potential field to match; name / offset match?");

			// check for the case where we have not been passed a 'potential field', but the given
			// 'var' is itself may be the field we seek, such as in an if statement like this:
			// 		if (color == RED)
			// where 'RED' is the variable we are checking
			String name = var.getName();
			int offset = var.getOffset();
			if (fieldMatcher.matches(name, offset)) {
				DtrfDbg.println(this, indent + "\tfield matcher matched on variable: " + var);
				return var;
			}

			DtrfDbg.println(this, indent + "\tNO FIELD MATCHER MATCH");
			return null; // we seek a field, but there is none
		}

		DtrfDbg.println(this, indent + "Checking 'potential field' match...");

		String name = potentialField.getName();
		int offset = potentialField.getOffset();
		if (fieldMatcher.matches(name, offset)) {
			DtrfDbg.println(this, indent + "\tMATCHED");
			return match;
		}
		DtrfDbg.println(this, indent + "\tNO MATCH");
		return null;
	}

	private DecompilerVariable getMatchingVarialbe(DataType dt, DecompilerVariable var,
			DecompilerVariable potentialField) {

		String indent = "\t\t\t";

		DtrfDbg.println(this, indent + "Checking for matching variable; any casts?");
		List<DecompilerVariable> castVariables = var.getCasts();
		for (DecompilerVariable cast : castVariables) {
			if (matchesType(cast, dt)) {
				DtrfDbg.println(this, indent + "MATCHED cast: " + cast);
				return cast;
			}
		}

		String dtString = dt == null ? "null" : dt.toString();
		DtrfDbg.println(this,
			indent + "No matched casts; checking type against var:\n" +
				StringUtilities.indentLines("type: " + dtString, indent + "\t") + "\n" +
				StringUtilities.indentLines("var: " + var.toString(), indent + "\t"));
		if (matchesType(var, dt)) {
			DtrfDbg.println(this, indent + "MATCHED type: ");
			return var;
		}

		DtrfDbg.println(this, indent + "Type did not match; checking High Variable: ");

		//
		// 						Unusual Code Alert!
		// It is a bit odd to check the field when you are looking for the type that contains the
		// field.  BUT, in the Decompiler, SOMETIMES the 'field' happens to have the data type of
		// the thing that contains it.  So, if you have:
		// 		foo.bar
		// then the 'bar' field will have a data type of Foo.   Unfortunately, this is not always
		// the case.  For now, when the variable is global, we need to check the field. Sad face
		// emoji.
		//
		HighVariable highVariable = var.variable.getHighVariable();
		if (highVariable instanceof HighGlobal) {
			if (matchesParentType(potentialField, dt)) {
				DtrfDbg.println(this, indent + "MATCHED on parent type: " + dt);
				return potentialField;
			}
		}

		DtrfDbg.println(this, indent + "NOT MATCHED");
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

		String indent = "\t\t\t\t";

		if (var == null) {
			DtrfDbg.println(this, indent + "Types Match? no variable to check");
			return false;
		}

		DataType varType = var.getDataType();
		if (varType == null) {
			// it seems odd to me that there is no type, but I have seen this in the case
			// statement of a switch
			DtrfDbg.println(this, indent + "ypes Match? no variable TYPE to check");
			return false;
		}
		boolean matches = isEqual(varType, dt);
		return matches;
	}

	protected DataTypeReference createReference(DecompilerVariable var) {

		DataType dataType = var.getDataType();
		LocationReferenceContext context = getContext(var);
		Function function = var.getFunction();
		Address address = getAddress(var);
		return new DataTypeReference(dataType, null, function, address, context);
	}

	private DataTypeReference createReference(DecompilerVariable var, DecompilerVariable field) {
		DataType dataType = var.getDataType();
		LocationReferenceContext context = getContext(var);
		Function function = var.getFunction();
		Address address = getAddress(var);
		return new DataTypeReference(dataType, field.getName(), function, address, context);
	}

	@Override
	protected LocationReferenceContext getContext(DecompilerVariable var) {
		DecompilerVariable field = findFieldFor(var);
		LocationReferenceContext context = super.getContext(field);
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
			"\tline " + getContext().getPlainText() + ",\n" +
			"\tfunction: " + getFunction() + "\n" +
			"\tvariable: " + StringUtilities.toStringWithIndent(variable) + ",\n" +
			"\tdata type: " + getDataType() + ",\n"+
			subFieldsString +
		"}";
		//@formatter:on
	}
}

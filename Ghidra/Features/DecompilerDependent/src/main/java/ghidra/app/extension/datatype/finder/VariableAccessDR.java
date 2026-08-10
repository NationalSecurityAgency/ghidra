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

import docking.widgets.search.SearchLocationContext;
import ghidra.app.decompiler.*;
import ghidra.app.services.DataTypeReference;
import ghidra.app.services.FieldMatcher;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
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

		// simplify how we search depending on whether a field is required and if we have fields
		if (fieldMatcher.isIgnored()) {
			accumulateMatchesForTypeOnly(dt, results);
			return;
		}

		if (fields.isEmpty()) {
			// We have a valid field matcher, but no fields.  Look for special case direct field
			// usage, such as an enum name used inline, without its containing class.
			accumulateMatchesDirectFields(dt, fieldMatcher, results);
			return;
		}

		/*
		 	This variable may have fields being accessed.  We need to check for the data type usage 
		 	in this variable and each of the fields that we find.  We need to make sure the fields 
		 	match as well.  For the given text below we will ask the following questions:
		 	
		 		Foo->bar->baz
		 		
		 		- Does Foo match the type and 'bar' match the field matcher?
		 		- Does bar match the type and 'baz' match the field matcher?
		 		- Does baz match the type?
		 		
		 		
		 	Known Special Cases:
		
		 		A) Foo is reported as the same type as bar:
		 			i.  both are actually the desired type
		 			ii. the field is not really the desired type
		 		B) Foo's type is not a Foo, bar's type is Foo instead
		 		
		 */

		DecompilerVariable parent = variable;
		for (DecompilerVariable field : fields) {

			// 1) See if the variable matches the type
			DataTypeReference ref = createStandardReference(dt, parent, field, fieldMatcher);
			if (ref != null) {
				results.add(ref);
				parent = field;
				continue;
			}

			// 2) See if both types match (case A from above)
			//    (At this point, either the parent type does not match, or the parent and the field
			//     share the same type.)
			ref = createReferenceWhenVariableAndFieldMatch(dt, parent, field, fieldMatcher);
			if (ref != null) {
				results.add(ref);
				parent = field;
				continue;
			}

			// 3) See if the field matches the type (case B from above)
			//    (At this point the variable doesn't match, or the field doesn't match.) 
			ref = createFieldReference(dt, parent, field, fieldMatcher);
			if (ref != null) {
				results.add(ref);
				parent = field;
				continue;
			}
		}

		// Note: since the last field in the loop above does not itself have a field, then it 
		// cannot match the requirement of a parent type followed by a field match.
	}

	private void accumulateMatchesForTypeOnly(DataType dt, List<DataTypeReference> results) {

		if (fields.isEmpty()) {
			// No fields to check.  See if this class's variable is a match.
			DecompilerVariable var = getMatchingVariable(dt, variable);
			if (var != null) {
				String fieldName = null;
				DataTypeReference ref = createReferenceToVariable(var, fieldName);
				results.add(ref);
			}
			return;
		}

		// This class's variable and each field may match the type.  In this loop we will check each
		// combination of a data type and the field, making a reference for all matches.  Each pass
		// through the loop makes the next field become the parent for the following field. The last
		// field is handled below the loop. 
		DecompilerVariable parent = variable;
		for (DecompilerVariable field : fields) {
			DecompilerVariable var = getMatchingVariable(dt, parent);
			parent = field;
			if (var == null) {
				continue; // the current 'parent' does not match
			}

			// Note: handle the bug condition where the variable and the field both have the type of
			// interest.
			DataTypeReference ref;
			DecompilerVariable preferred = updateVarForBugCondition(var, field);
			if (preferred == var) {
				String fieldName = field.getName();
				ref = createReferenceToVariable(var, fieldName);
			}
			else { // preferred == field

				// if we encounter the bug condition where the field is the actual type we seek, 
				// then don't use the field name, as the field is the reference.
				String fieldName = null;
				ref = createReferenceToField(preferred, fieldName);
			}

			results.add(ref);
		}

		// Handle the last field.  In this case, we cannot have a parent and field match, only a 
		// match on the data type with no field.
		DecompilerVariable var = getMatchingVariable(dt, parent);
		if (var != null) {
			String fieldName = null;
			DataTypeReference ref = createReferenceToVariable(var, fieldName);
			results.add(ref);
		}
	}

	private DecompilerVariable updateVarForBugCondition(DecompilerVariable var,
			DecompilerVariable field) {

		if (isFieldTheBetterMatch(var, field)) {
			// assume a real match for a self-referencing structure
			return field;
		}

		return var;
	}

	private boolean isFieldTheBetterMatch(DecompilerVariable var, DecompilerVariable field) {

		// This is an odd case where both the parent and the field have the same type.  This may be 
		// valid, such as when a structure contains a reference to itself.  But, this also can 
		// happen when the decompiler makes mistakes when setting the data type.

		// This type may not be the actual field type.  We check on that below when these types are
		// the same.
		DataType fdt = field.getDataType();
		DataType vdt = var.getDataType();
		if (!isEqual(vdt, fdt)) {
			return false; // the original var is the correct variable
		}

		// We have the same type.  If the 2 types are really the same (self-refernecing structure),
		// then we want a match for the parent to the field.  If the types are not really the same,
		// then for now assume the field itself is the correct match.

		// Note: this had been using 'sourceToken', which doesn't seem right.  If we find missed 
		// cases where 'field.variable' is not working, then revisit using 'sourceToken' as a 
		// fallback check.
		//ClangFieldToken fieldToken = (ClangFieldToken) sourceToken;
		if (!(field.variable instanceof ClangFieldToken fieldToken)) {
			return false; // cannot check the field's type
		}

		DataType actualFieldDt = DecompilerReference.getFieldDataType(fieldToken);
		boolean matchesFieldType = isEqual(vdt, actualFieldDt);
		if (matchesFieldType) {
			// assume a real match for a self-referencing structure
			return true;
		}

		return false;
	}

	private void accumulateMatchesDirectFields(DataType dt, FieldMatcher fieldMatcher,
			List<DataTypeReference> results) {

		DecompilerVariable var = getMatch(dt, fieldMatcher, variable);
		if (var != null) {
			String fieldName = fieldMatcher.getFieldName();
			DataTypeReference ref = createReferenceToField(var, fieldName);
			results.add(ref);
		}
	}

	private DataTypeReference createStandardReference(DataType dt, DecompilerVariable parent,
			DecompilerVariable field, FieldMatcher fieldMatcher) {

		// a standard reference is the case where the parent is the type we seek and the field 
		// matches the matcher
		DecompilerVariable var = getMatchingVariable(dt, parent);
		if (var == null) {
			return null;
		}

		DataType vdt = var.getDataType();
		DataType fdt = field.getDataType();
		if (isEqual(vdt, fdt)) {
			return null; // this may be an error case; handled by a different method later
		}

		String fieldName = field.getName();
		int offset = field.getOffset();
		if (fieldMatcher.matches(fieldName, offset)) {
			return createReference(var, field, fieldMatcher);
		}

		return null;
	}

	private DataTypeReference createFieldReference(DataType dt, DecompilerVariable parent,
			DecompilerVariable field, FieldMatcher fieldMatcher) {

		// Note: this method should only be called if we did not create a 'standard reference', 
		// which is when the parent type matches 'dt' and the field type does not match.  Getting 
		// into this method means either the parent type did not match, or the parent and field both
		// match the type.

		/*
		 	This is the case where the parent variable was not the correct type, but we need to see
			if the field itself is the type we seek.  I believe this comment describes this case:
		 	
		 	// check for the case where the given 'field' may be the type we seek, such as in an if
		 	// statement like this:
			// 		if (color == RED)
			// where 'RED' is the variable we are checking
		 */
		HighVariable highVariable = parent.variable.getHighVariable();
		if (highVariable == null) {
			return null; // not sure of the significance of this check
		}

		if (!matchesParentType(field, dt)) {
			return null;
		}

		String fieldName = field.getName();
		int offset = field.getOffset();
		if (fieldMatcher.matches(fieldName, offset)) {
			// the field matches the type and the name
			return createReference(field, field, fieldMatcher);
		}
		return null;
	}

	private DataTypeReference createReferenceWhenVariableAndFieldMatch(DataType dt,
			DecompilerVariable parent, DecompilerVariable field, FieldMatcher fieldMatcher) {

		// This is an odd case where both the parent and the field have the same type.  This may be 
		// valid, such as when a structure contains a reference to itself.  But, this also can 
		// happen when the decompiler makes mistakes when setting the data type.
		DecompilerVariable var = getMatchingVariable(dt, parent);
		if (var == null) {
			return null;
		}

		String name = field.getName();
		int offset = field.getOffset();
		if (!fieldMatcher.matches(name, offset)) {
			return null;
		}

		if (isFieldTheBetterMatch(var, field)) {
			// this implies a self-referential structure; create a reference to the field
			return createReference(field, field, fieldMatcher);
		}

		// At this point, the parent matches the data type, but the field itself is not actually
		// a data type match.  Also, since we checked above, we know the field name matches. Create
		// a standard reference.
		return createReference(var, field, fieldMatcher);
	}

	private DecompilerVariable getMatch(DataType dt, FieldMatcher fieldMatcher,
			DecompilerVariable var) {

		String indent = "\t\t\t";

		DecompilerVariable match = getMatchingVariable(dt, var);
		if (match == null) {
			DtrfDbg.println(getFunction(), this, indent + "NO MATCHING VARIABLE");
			return null; // wrong type, nothing to do
		}

		// check for the case where we have not been passed a 'potential field', but the given
		// 'var' is itself may be the field we seek, such as in an if statement like this:
		// 		if (color == RED)
		// where 'RED' is the variable we are checking
		String name = var.getName();
		int offset = var.getOffset();
		if (fieldMatcher.matches(name, offset)) {
			StringUtilities.indentLines(var.toString(), indent + '\t');
			DtrfDbg.println(getFunction(), this,
				indent + "\tfield matcher matched on variable: " + var);
			return var;
		}

		DtrfDbg.println(getFunction(), this, indent + "\tNO FIELD MATCHER MATCH");
		return null; // we seek a field, but there is none
	}

	// return the first matching cast for the given variable, if any
	private DecompilerVariable getFirstMatchingCast(DataType dt, DecompilerVariable var) {

		String indent = "\t\t\t";

		DtrfDbg.println(getFunction(), this, indent +
			"Checking for matching variable (no fields); any casts?");
		List<DecompilerVariable> castVariables = var.getCasts();
		for (DecompilerVariable cast : castVariables) {
			if (matchesType(cast, dt)) {
				DtrfDbg.println(getFunction(), this, indent + "MATCHED cast: " + cast);
				return cast;
			}
		}
		return null;
	}

	private DecompilerVariable getMatchingVariable(DataType dt, DecompilerVariable var) {

		String indent = "\t\t\t";

		// Note: for now, we ignore the precedence of casting; if any cast type is a match, then
		//       signal hooray
		DecompilerVariable cast = getFirstMatchingCast(dt, var);
		if (cast != null) {
			// assume that any match in the cast implies we will not match a variable access
			return cast;
		}

		String dtString = dt == null ? "null" : dt.toString();
		DtrfDbg.println(getFunction(), this,
			indent + "No matched casts; checking type against var:\n" +
				StringUtilities.indentLines("type: " + dtString, indent + "\t") + "\n" +
				StringUtilities.indentLines("var: " + var.toString(), indent + "\t"));
		if (matchesType(var, dt)) {
			DtrfDbg.println(getFunction(), this, indent + "MATCHED type: ");
			return var;
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

		String indent = "\t\t\t\t";

		if (var == null) {
			DtrfDbg.println(getFunction(), this, indent + "Types Match? no variable to check");
			return false;
		}

		DataType varType = var.getDataType();
		if (varType == null) {
			// it seems odd to me that there is no type, but I have seen this in the case
			// statement of a switch
			DtrfDbg.println(getFunction(), this, indent + "Types Match? no variable TYPE to check");
			return false;
		}
		boolean matches = isEqual(varType, dt);
		return matches;
	}

	protected DataTypeReference createReferenceToVariable(DecompilerVariable var,
			String fieldName) {
		DataType dataType = var.getDataType();
		SearchLocationContext context = getContextForVariable(var);
		Function function = var.getFunction();
		Address address = getAddress(var);
		return new DataTypeReference(dataType, fieldName, function, address, context);
	}

	protected DataTypeReference createReferenceToField(DecompilerVariable field,
			String fieldName) {
		DataType dataType = field.getDataType();
		SearchLocationContext context = getContextForField(field);
		Function function = field.getFunction();
		Address address = getAddress(field);
		return new DataTypeReference(dataType, fieldName, function, address, context);
	}

	private DataTypeReference createReference(DecompilerVariable var, DecompilerVariable field,
			FieldMatcher fieldMatcher) {
		DataType dataType = var.getDataType();
		SearchLocationContext context = getContext(var, fieldMatcher);
		Function function = var.getFunction();
		Address address = getAddress(var);
		String fieldName = field != null ? field.getName() : null;
		return new DataTypeReference(dataType, fieldName, function, address, context);
	}

	@Override
	protected SearchLocationContext getContext(DecompilerVariable var) {
		// Default to highlighting the field that is being called on the given variable.  Clients of
		// this method may choose to highlight the variable itself, in which case they should call
		// getContextForVariable(var).
		return getContextForField(var);
	}

	private SearchLocationContext getContextForVariable(DecompilerVariable var) {
		return super.getContext(var);
	}

	protected SearchLocationContext getContextForField(DecompilerVariable var) {
		DecompilerVariable field = findFieldFor(var);
		SearchLocationContext context = super.getContext(field);
		return context;
	}

	protected SearchLocationContext getContext(DecompilerVariable var, FieldMatcher fieldMatcher) {
		if (fieldMatcher.isIgnored()) {
			// when there is not field to match, we only want to highlight the variable itself
			return super.getContext(var);
		}

		// assume that a valid field matcher means that we have already matched before this call,
		// so use the matching field for the context highlight
		return getContextForField(var);
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
		if (variable == null) {
			return "<uninialized>";
		}

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

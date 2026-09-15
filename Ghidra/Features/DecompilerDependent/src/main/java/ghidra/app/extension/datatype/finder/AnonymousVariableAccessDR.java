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

import docking.widgets.search.SearchLocationContext;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.services.DataTypeReference;
import ghidra.app.services.FieldMatcher;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;

/**
 * This class represents the use of a field of a {@link Composite} data type <b>where there is no
 * variable in the Decompiler</b> for that data type.   A normal variable access in the Decompiler
 * may look like so:
 * <pre>
 * 	Foo f;
 * 	...
 * 	return f.some_field;
 * </pre>
 *
 * Alternatively, an anonymous variable access would look like this:
 * <pre>
 *	Bar b;
 * 	...
 *	return b-><b>foo_array[1].some_field</b>;
 * </pre>
 *
 * In this case, <code><b>foo_array[1]</b></code> is a <code>Foo</code>, whose
 * <code><b>some_field</b></code> is being accessed anonymously, since there is no variable of
 * <code>Foo</code> declared in the current function.
 */
public class AnonymousVariableAccessDR extends VariableAccessDR {

	protected AnonymousVariableAccessDR(ClangLine line, ClangFieldToken token) {
		super(line, token);
	}

	@Override
	public void accumulateMatches(DataType dt, FieldMatcher fieldMatcher,
			List<DataTypeReference> results) {

		//
		// This class is backed by a ClangFieldToken.  That class's data type is the composite that
		// contains the field being accessed.   A variable being accessed has 2 types being
		// touched: the aforementioned composite and the type of the field itself.
		//
		// This can match in one of two cases:
		// 1) the passed in type must match the field type and not the parent type, or
		// 2) the passed in type must match the parent type, along with supplied field name/offset.
		//

		ClangFieldToken field = (ClangFieldToken) sourceToken;
		DataType compositeType = field.getDataType();
		DataType fieldDt = DecompilerReference.getFieldDataType(field);

		boolean matchesCompositeType = isEqual(dt, compositeType);
		boolean matchesFieldType = isEqual(dt, fieldDt);
		boolean noMatch = !(matchesCompositeType || matchesFieldType);
		if (noMatch) {
			return;
		}

		//
		// Case 1
		//
		// If the client did not specify a field to match, then we only want to match on the type
		// of this reference's field type and NOT the composite type, since this reference is
		// referring to the field and not the composite.
		//
		if (fieldMatcher.isIgnored()) {

			if (matchesFieldType) {
				// no field to match and the search type matches this composite's field type
				String fieldName = null;
				DataTypeReference ref = createReferenceToVariable(variable, fieldName);
				results.add(ref);
			}

			// else there is no field to match and the search type matched the composite type; as 
			// mentioned in the comment above, we are ignoring the match on the composite, as 
			// that is handled by the VariableAccessDR, which gets created before this object as the
			// tokens are being parsed.
			return;
		}

		//
		// Case 2
		//
		// The client has requested a particular field of the parent composite.  We only have a
		// match if the parent type matches and the field name/offset matches.
		//
		String fieldName = field.getText();
		int offset = field.getOffset();
		if (!fieldMatcher.matches(fieldName, offset)) {
			return; // the field does not match
		}

		if (matchesCompositeType) {
			Function function = getFunction();
			Address address = getAddress();
			SearchLocationContext context = getContext();
			results.add(
				new DataTypeReference(compositeType, fieldName, function, address, context));
		}
		// else,  matches the composite's field type, but not the parent type; this fails the 
		// requirement that the composite type must match when searching for a field
	}
}

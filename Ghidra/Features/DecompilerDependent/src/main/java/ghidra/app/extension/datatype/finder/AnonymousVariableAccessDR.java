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

import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.services.DataTypeReference;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;

/**
 * This class represents the use of a field of a {@link Composite} data type <b>where there is
 * no variable in the Decompiler</b> for that data type.   A normal variable access in the
 * Decompiler may look like so:
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
 * <code><b>some_field</b></code> is 
 * being accessed anonymously, since there is no variable of <code>Foo</code> declared 
 * in the current function. 
 */
public class AnonymousVariableAccessDR extends DecompilerReference {

	protected AnonymousVariableAccessDR(ClangLine line, ClangFieldToken token) {
		super(line, token);
	}

	@Override
	public void accumulateMatches(DataType dt, String fieldName, List<DataTypeReference> results) {

		ClangFieldToken field = (ClangFieldToken) sourceToken;
		DataType fieldDt = field.getDataType();
		if (!isEqual(dt, fieldDt)) {
			return;
		}

		if (field.getText().equals(fieldName)) {
			results.add(new DataTypeReference(fieldDt, fieldName, getFunction(), getAddress(),
				getContext()));
		}
	}

}

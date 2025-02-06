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
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContextBuilder;
import ghidra.app.services.DataTypeReference;
import ghidra.app.services.FieldMatcher;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.util.StringUtilities;

/**
 * A reference to a place as told by the Decompiler.
 */
public abstract class DecompilerReference {

	protected ClangLine line;
	protected ClangToken sourceToken;
	protected DecompilerVariable variable;

	protected DecompilerReference(ClangLine line, ClangToken token) {
		this.line = line;
		this.sourceToken = token;

		// if token is null, then it will be filled-in later
		if (token != null) {
			this.variable = new DecompilerVariableType(token);
		}
	}

	/**
	 * Scan this reference for any data type matches.
	 * <p>
	 * The {@code fieldName} is optional.  If not included, then only data type matches will
	 * be sought.  If it is included, then a match is only included when it is a reference
	 * to the given data type where that type is being accessed by the given field name.
	 *
	 * @param dt the data type to find
	 * @param fieldMatcher the optional field matcher used to restrict matches.
	 * @param results the accumulator object into which will be placed any matches
	 */
	public abstract void accumulateMatches(DataType dt, FieldMatcher fieldMatcher,
			List<DataTypeReference> results);

	public DecompilerVariable getVariable() {
		return variable;
	}

	// Note: this is overridden when getting data types is more complicated (like when casting
	//       is involved).
	public DataType getDataType() {
		return variable.getDataType();
	}

	public Function getFunction() {
		Function function = variable.getFunction();
		return function;
	}

	public Address getAddress() {
		return variable.getAddress();
	}

	public Address getAddress(DecompilerVariable var) {
		return var.getAddress();
	}

	public ClangLine getLine() {
		return line;
	}

	protected LocationReferenceContext getContext() {
		LocationReferenceContext context = getContext(variable);
		return context;
	}

	protected LocationReferenceContext getContext(DecompilerVariable var) {

		LocationReferenceContextBuilder builder = new LocationReferenceContextBuilder();
		builder.append(line.getLineNumber() + ": ");
		List<ClangToken> tokens = line.getAllTokens();
		for (ClangToken token : tokens) {
			if (token.equals(var.variable)) {
				builder.appendMatch(token.getText());
			}
			else {
				builder.append(token.getText());
			}
		}
		return builder.build();
	}

	// Note: using isEquivalent() allows different data types to match.  I don't think we want
	//       that.  This can be deleted in a few versions if we no longer need it.
	public static boolean isEquivalent(DataType dt1, DataType dt2) {
		DataType base1 = getBaseType(dt1);
		DataType base2 = getBaseType(dt2);

		if (base1 == null || base2 == null) {
			// this should not happen, but we have seen sometimes that ClangVariableDecl
			// cannot find its HighSymbol from which to get a datatype
			return false;
		}

		return base1.isEquivalent(base2);
	}

	public static boolean isEqual(DataType dt1, DataType dt2) {
		DataType base1 = getBaseType(dt1);
		DataType base2 = getBaseType(dt2);

		if (base1 == null || base2 == null) {
			// this should not happen, but we have seen sometimes that ClangVariableDecl
			// cannot find its HighSymbol from which to get a datatype
			return false;
		}

		return base1.equals(base2);
	}

	public static DataType getBaseType(DataType dt) {
		if (dt instanceof Array) {
			return getBaseType(((Array) dt).getDataType());
		}
		else if (dt instanceof Pointer) {
			DataType baseDataType = ((Pointer) dt).getDataType();
			if (baseDataType != null) {
				return getBaseType(baseDataType);
			}
		}
		else if (dt instanceof TypeDef) {
			DataType baseDataType = ((TypeDef) dt).getBaseDataType();
			return getBaseType(baseDataType);
		}
		return dt;
	}

	public static DataType getFieldDataType(ClangFieldToken field) {
		DataType fieldDt = field.getDataType();
		fieldDt = DecompilerReference.getBaseType(fieldDt);
		if (fieldDt instanceof Structure parent) {
			int offset = field.getOffset();
			int n = parent.getLength();
			if (offset >= 0 && offset < n) {
				DataTypeComponent dtc = parent.getComponentContaining(field.getOffset());
				if (dtc != null) {
					return dtc.getDataType();
				}
			}
		}

		return fieldDt;
	}

	@Override
	public String toString() {

		//@formatter:off
		return "{\n" +
			"\tvariable: " + StringUtilities.toStringWithIndent(variable) + ",\n" +
			"\tdata type: " + getDataType() + ",\n"+
			"\tline " + StringUtilities.toStringWithIndent(getContext().getPlainText()) + ",\n" +
			"\tfunction: " + getFunction() + "\n" +
		"}";
		//@formatter:on
	}
}

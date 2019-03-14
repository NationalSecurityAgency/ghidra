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
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

/**
 * A class that represents access to a Decompiler {@link ClangFieldToken} object.  This is the field 
 * of a variable, denoted by {@link ClangVariableToken}.
 */
public class DecompilerFieldAccess extends DecompilerVariable {

	// for building on-the-fly
	DecompilerFieldAccess() {
		super(null);
	}

	DecompilerFieldAccess(ClangFieldToken field, List<DecompilerVariable> casts) {
		super(field);
		this.casts = casts;
	}

	@Override
	public DataType getParentDataType() {
		ClangFieldToken field = (ClangFieldToken) variable;
		DataType dt = field.getDataType();
		return dt;
	}

	@Override
	public DataType getDataType() {
		ClangFieldToken field = (ClangFieldToken) variable;
		DataType dt = field.getDataType();
		dt = getBaseType(dt);
		if (!(dt instanceof Composite)) {
			// can the dt be a pointer?
			Msg.error(this, "Have a field for a type that is not a Composite type");
			return dt;
		}

		int offset = field.getOffset();
		Composite composite = (Composite) dt;
		if (composite instanceof Structure) {
			DataTypeComponent subType = ((Structure) composite).getComponentAt(offset);
			if (subType != null) {
				return subType.getDataType();
			}
		}

		DataTypeComponent component = composite.getComponent(offset);
		if (component == null) {
			return null; // not sure what else to do
		}
		dt = component.getDataType();
		return dt;
	}

	protected DataType getBaseType(DataType dt) {
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
			return getBaseType(((TypeDef) dt).getBaseDataType());
		}
		return dt;
	}
}

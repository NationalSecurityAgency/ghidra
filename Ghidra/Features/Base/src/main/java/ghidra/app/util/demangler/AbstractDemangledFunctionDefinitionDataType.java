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
package ghidra.app.util.demangler;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.data.*;
import ghidra.program.model.symbol.Namespace;

/**
 * Parent base class for types that represent things that refer to functions
 */
public abstract class AbstractDemangledFunctionDefinitionDataType extends DemangledDataType {

	protected static final String DEFAULT_NAME_PREFIX = "FuncDef";
	protected static final String EMPTY_STRING = "";
	protected static int ID = 0;
	protected DemangledDataType returnType;
	protected String callingConvention;// __cdecl, __thiscall, etc.
	protected List<DemangledDataType> parameters = new ArrayList<>();
	protected String modifier;// namespace::, etc.
	protected boolean isConstPointer;

	protected String parentName;
	protected boolean isTrailingPointer64;
	protected boolean isTrailingUnaligned;
	protected boolean isTrailingRestrict;

	/** display parens in front of parameter list */
	protected boolean displayFunctionPointerParens = true;

	AbstractDemangledFunctionDefinitionDataType(String mangled, String originalDemangled) {
		super(mangled, originalDemangled, DEFAULT_NAME_PREFIX + nextId());
	}

	private synchronized static int nextId() {
		return ID++;
	}

	/**
	 * Returns the string for this type of reference (e.g., * or &)
	 * @return the string
	 */
	abstract protected String getTypeString();

	@Override
	public String getSignature() {
		return toSignature(null);
	}

	/**
	 * Sets the return type
	 * @param returnType the return type
	 */
	public void setReturnType(DemangledDataType returnType) {
		this.returnType = returnType;
	}

	/**
	 * Returns the return type
	 * @return the return type
	 */
	public DemangledDataType getReturnType() {
		return returnType;
	}

	/**
	 * Sets the function calling convention. For example, "__cdecl"
	 * @param callingConvention the function calling convention
	 */
	public void setCallingConvention(String callingConvention) {
		this.callingConvention = callingConvention;
	}

	/**
	 * Returns the calling convention or null, if unspecified
	 * @return the calling convention or null, if unspecified
	 */
	public String getCallingConvention() {
		return callingConvention;
	}

	/**
	 * Sets the function __ modifier. For example, "namespace::".
	 * @param modifier the function modifier
	 */
	public void setModifier(String modifier) {
		this.modifier = modifier;
	}

	public boolean isConstPointer() {
		return isConstPointer;
	}

	public void setConstPointer() {
		isConstPointer = true;
	}

	public boolean isTrailingPointer64() {
		return isTrailingPointer64;
	}

	public void setTrailingPointer64() {
		isTrailingPointer64 = true;
	}

	public boolean isTrailingUnaligned() {
		return isTrailingUnaligned;
	}

	public void setTrailingUnaligned() {
		isTrailingUnaligned = true;
	}

	public boolean isTrailingRestrict() {
		return isTrailingRestrict;
	}

	public void setTrailingRestrict() {
		isTrailingRestrict = true;
	}

	public void setDisplayFunctionPointerParens(boolean b) {
		this.displayFunctionPointerParens = b;
	}

	/**
	 * Adds a parameters to the end of the parameter list for this demangled function
	 * @param parameter the new parameter to add
	 */
	public void addParameter(DemangledDataType parameter) {
		parameters.add(parameter);
	}

	/**
	 * Returns a list of the parameters for this demangled functions.
	 * @return a list of the parameters for this demangled functions
	 */
	public List<DemangledDataType> getParameters() {
		return new ArrayList<>(parameters);
	}

	public String toSignature(String name) {
		StringBuilder buffer = new StringBuilder();
		StringBuilder buffer1 = new StringBuilder();
		String s = getConventionPointerNameString(name);
		if (s.contains(" ") || s.isEmpty()) {
			// spaces--add parens
			addFunctionPointerParens(buffer1, s);
		}
		else { // this allows the '__cdecl' in templates to not have parens
			buffer1.append(s);
		}

		buffer1.append('(');
		for (int i = 0; i < parameters.size(); ++i) {
			buffer1.append(parameters.get(i).getSignature());
			if (i < parameters.size() - 1) {
				buffer1.append(',');
			}
		}
		buffer1.append(')');

		if (returnType instanceof DemangledFunctionPointer) {
			DemangledFunctionPointer dfp = (DemangledFunctionPointer) returnType;
			buffer.append(dfp.toSignature(buffer1.toString())).append(SPACE);
		}
		else if (returnType instanceof DemangledFunctionReference) {
			DemangledFunctionReference dfr = (DemangledFunctionReference) returnType;
			buffer.append(dfr.toSignature(buffer1.toString())).append(SPACE);
		}
		else if (returnType instanceof DemangledFunctionIndirect) {
			DemangledFunctionIndirect dfi = (DemangledFunctionIndirect) returnType;
			buffer.append(dfi.toSignature(buffer1.toString())).append(SPACE);
		}
		else {
			buffer.append(returnType.getSignature()).append(SPACE);
			buffer.append(buffer1);
		}

		if (isConst()) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(CONST);
		}

		if (isVolatile()) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(VOLATILE);
		}

		if (isTrailingUnaligned) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(UNALIGNED);
		}

		if (isTrailingPointer64) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(PTR64);
		}

		if (isTrailingRestrict) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(RESTRICT);
		}

		return buffer.toString();
	}

	protected String getConventionPointerNameString(String name) {
		StringBuilder buffer = new StringBuilder();
		buffer.append(callingConvention == null ? EMPTY_STRING : callingConvention);

		int pointerLevels = getPointerLevels();
		if (pointerLevels > 0) {
			if (callingConvention != null) {
				buffer.append(SPACE);
			}

			addParentName(buffer);

			for (int i = 0; i < pointerLevels; ++i) {
				buffer.append(getTypeString());
			}
		}

		if ((modifier != null) && (modifier.length() != 0)) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(modifier);
		}

		if (isConstPointer) {
			buffer.append(CONST);
		}

		if (isPointer64()) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(PTR64);
		}

		if (name != null) {
			if ((buffer.length() > 2) && (buffer.charAt(buffer.length() - 1) != SPACE)) {
				buffer.append(SPACE);
			}
			buffer.append(name);
		}

		return buffer.toString();
	}

	protected void addFunctionPointerParens(StringBuilder buffer, String s) {
		if (!displayFunctionPointerParens) {
			return;
		}

		buffer.append('(').append(s).append(')');
	}

	protected void addParentName(StringBuilder buffer) {
		if (parentName == null) {
			return;
		}

		if (parentName.startsWith(DEFAULT_NAME_PREFIX)) {
			return;
		}

		if (buffer.length() > 2) {
			char lastChar = buffer.charAt(buffer.length() - 1);
			if (SPACE != lastChar) {
				buffer.append(SPACE);
			}
		}
		buffer.append(parentName).append(Namespace.DELIMITER);
	}

	@Override
	public DataType getDataType(DataTypeManager dataTypeManager) {

		FunctionDefinitionDataType fddt = new FunctionDefinitionDataType(getName());

		if (returnType != null) {
			fddt.setReturnType(returnType.getDataType(dataTypeManager));
		}

		if (parameters.size() != 1 ||
			!(parameters.get(0).getDataType(dataTypeManager) instanceof VoidDataType)) {
			ParameterDefinition[] params = new ParameterDefinition[parameters.size()];
			for (int i = 0; i < parameters.size(); ++i) {
				params[i] = new ParameterDefinitionImpl(null,
					parameters.get(i).getDataType(dataTypeManager), null);
			}
			fddt.setArguments(params);
		}

		DataType dt = DemangledDataType.findDataType(dataTypeManager, namespace, getName());
		if (dt == null || !(dt instanceof FunctionDefinitionDataType)) {
			dt = fddt;
		}

		return new PointerDataType(dt, dataTypeManager);
	}
}

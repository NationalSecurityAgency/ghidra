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

import org.apache.commons.lang3.StringUtils;

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

	AbstractDemangledFunctionDefinitionDataType(String mangled, String originalDemangled) {
		super(mangled, originalDemangled, DEFAULT_NAME_PREFIX + nextId());
	}

	private synchronized static int nextId() {
		return ID++;
	}

	/**
	 * Returns the string for this type of reference (e.g., * or &amp;)
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

		addFunctionPointerParens(buffer1, s);

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

		StringBuilder typeBuffer = new StringBuilder();
		int pointerLevels = getPointerLevels();
		if (pointerLevels > 0) {

			addParentName(typeBuffer);

			for (int i = 0; i < pointerLevels; ++i) {
				typeBuffer.append(getTypeString());
			}
		}

		if (!StringUtils.isBlank(typeBuffer)) {

			if (!StringUtils.isBlank(callingConvention)) {
				buffer.append(SPACE);
			}

			buffer.append(typeBuffer);
		}

		addModifier(buffer);

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
			if ((buffer.length() > 0) && (buffer.charAt(buffer.length() - 1) != SPACE)) {
				buffer.append(SPACE);
			}
			buffer.append(name);
		}

		return buffer.toString();
	}

	private void addModifier(StringBuilder buffer) {
		if (StringUtils.isBlank(modifier)) {
			return;
		}

		//
		// Guilty knowledge: in many cases the 'modifier' is the same as the type string.  Further,
		// when we print signatures, we will print the type string if there are pointer levels. To
		// prevent duplication, do not print the modifier when it matches the type string and we
		// will be printing the type string (which is printed when there are pointer levels).
		//
		if (modifier.equals(getTypeString()) &&
			getPointerLevels() > 0) {
			return;
		}

		if (buffer.length() > 2) {
			buffer.append(SPACE);
		}
		buffer.append(modifier);
	}

	protected void addFunctionPointerParens(StringBuilder buffer, String s) {
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

		setParameters(fddt, dataTypeManager);

		DataType dt = DemangledDataType.findDataType(dataTypeManager, namespace, getName());
		if (dt == null || !(dt instanceof FunctionDefinitionDataType)) {
			dt = fddt;
		}

		return new PointerDataType(dt, dataTypeManager);
	}

	private void setParameters(FunctionDefinitionDataType fddt, DataTypeManager dataTypeManager) {
		if (hasSingleVoidParameter(dataTypeManager)) {
			return;
		}

		ParameterDefinition[] params = new ParameterDefinition[parameters.size()];
		for (int i = 0; i < parameters.size(); ++i) {
			params[i] = new ParameterDefinitionImpl(null,
				parameters.get(i).getDataType(dataTypeManager), null);
		}
		fddt.setArguments(params);
	}

	private boolean hasSingleVoidParameter(DataTypeManager dataTypeManager) {
		if (parameters.size() != 1) {
			return false;
		}

		DemangledDataType parameter = parameters.get(0);
		DataType dt = parameter.getDataType(dataTypeManager);
		return dt instanceof VoidDataType;
	}
}

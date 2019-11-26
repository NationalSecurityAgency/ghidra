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

/**
 * A class to represent a demangled function indirect.  A function indirect is
 * similar to a function pointer or a function reference except that it does
 * not have the start (*) for a pointer or ampersand (&amp;) for a reference, but
 * is still an indirect definition (not a regular function definition).  The
 * function indirect is prevalent in the Microsoft model, if not other models.
 */
public class DemangledFunctionIndirect extends DemangledDataType implements ParameterReceiver {

	private static final String DEFAULT_NAME_PREFIX = "FuncDef";
	private static final String NAMESPACE_DELIMITER = "::";
	private static final String EMPTY_STRING = "";
	private static int ID = 0;
	private DemangledDataType returnType;
	protected String callingConvention;// __cdecl, __thiscall, etc.
	private List<DemangledDataType> parameters = new ArrayList<>();
	protected String modifier;// namespace::, etc.
	protected boolean isConstPointer;

	private String parentName;
	private boolean isTrailingPointer64;
	private boolean isTrailingUnaligned;
	private boolean isTrailingRestrict;

	/** display parens in front of parameter list */
	private boolean displayFunctionPointerParens = true;

	/**
	 * Constructs a new demangled function definition.
	 */
	public DemangledFunctionIndirect() {
		super("FuncDef" + nextID());
	}

	private synchronized static int nextID() {
		return ID++;
	}

//	DemangledFunctionDefinition(GenericDemangledFunctionDefinition generic) {
//		super(generic);
//
//		ID = generic.getID();
//		returnType = (DemangledDataType) DemangledObjectFactory.convert(generic.getReturnType());
//		callingConvention = generic.getCallingConvention();
//		isConstPointer = generic.isConstPointer();
//
//		parentName = generic.getParentName();
//		isTrailingPointer64 = generic.isTrailingPointer64();
//
//		List<GenericDemangledDataType> genericParameters = generic.getParameters();
//		for (GenericDemangledDataType parameter : genericParameters) {
//			parameters.add((DemangledDataType) DemangledObjectFactory.convert(parameter));
//		}
//	}

	/**
	 * Returns the return type.
	 * @return the return type
	 */
	public DemangledDataType getReturnType() {
		return returnType;
	}

	/**
	 * Sets the return type.
	 * @param returnType the return type
	 */
	public void setReturnType(DemangledDataType returnType) {
		this.returnType = returnType;
	}

	/**
	 * Returns the calling convention or null, if unspecified.
	 * @return the calling convention or null, if unspecified
	 */
	public String getCallingConvention() {
		return callingConvention;
	}

	/**
	 * Sets the function calling convention. For example, "__cdecl".
	 * @param callingConvention the function calling convention
	 */
	public void setCallingConvention(String callingConvention) {
		this.callingConvention = callingConvention;
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
	 * Adds a parameters to the end of the parameter list for 
	 * this demangled function.
	 * @param parameter the new parameter to add
	 */
	@Override
	public void addParameter(DemangledDataType parameter) {
		parameters.add(parameter);
	}

	/**
	 * Returns a list of the parameters for this demangled functions.
	 * @return a list of the parameters for this demangled functions
	 */
	@Override
	public List<DemangledDataType> getParameters() {
		return new ArrayList<>(parameters);
	}

	@Override
	public DemangledDataType copy() {
		DemangledFunctionIndirect copy = new DemangledFunctionIndirect();
		copy(this, copy);
		return copy;
	}

	@Override
	protected void copy(DemangledDataType source, DemangledDataType destination) {
		super.copy(source, destination);
		if ((source instanceof DemangledFunctionIndirect) &&
			(destination instanceof DemangledFunctionIndirect)) {
			DemangledFunctionIndirect copySource = (DemangledFunctionIndirect) source;
			DemangledFunctionIndirect copyDestination = (DemangledFunctionIndirect) destination;

			copyDestination.returnType = copySource.returnType.copy();
			for (DemangledDataType parameter : copySource.parameters) {
				copyDestination.parameters.add(parameter.copy());
			}

			copyDestination.callingConvention = copySource.callingConvention;
		}
	}

	@Override
	public String toSignature() {
		return toSignature(null);
	}

	public String toSignature(String name) {
		StringBuffer buffer = new StringBuffer();
		StringBuffer buffer1 = new StringBuffer();
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
			buffer1.append(parameters.get(i).toSignature());
			if (i < parameters.size() - 1) {
				buffer1.append(',');
			}
		}
		buffer1.append(')');

		if (returnType instanceof DemangledFunctionPointer) {
			buffer.append(
				((DemangledFunctionPointer) returnType).toSignature(buffer1.toString())).append(
					SPACE);
		}
		else if (returnType instanceof DemangledFunctionReference) {
			buffer.append(
				((DemangledFunctionReference) returnType).toSignature(buffer1.toString())).append(
					SPACE);
		}
		else if (returnType instanceof DemangledFunctionIndirect) {
			buffer.append(
				((DemangledFunctionIndirect) returnType).toSignature(buffer1.toString())).append(
					SPACE);
		}
		else {
			buffer.append(returnType.toSignature()).append(SPACE);
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

	private void addFunctionPointerParens(StringBuffer buffer, String s) {
		if (!displayFunctionPointerParens) {
			return;
		}

		buffer.append('(').append(s).append(')');
	}

	private String getConventionPointerNameString(String name) {
		StringBuilder buffer = new StringBuilder();
		buffer.append(callingConvention == null ? EMPTY_STRING : callingConvention);

		int pointerLevels = getPointerLevels();
		if (pointerLevels > 0) {
//			if (callingConvention != null) {
//				buffer.append(SPACE);
//			}

			addParentName(buffer);

//			for (int i = 0; i < pointerLevels; ++i) {
//				buffer.append('*');
//			}
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
//			if (buffer.length() > 2) {
//				buffer.append(SPACE);
//			}
			if ((buffer.length() > 2) && (buffer.charAt(buffer.length() - 1) != SPACE)) {
				buffer.append(SPACE);
			}
			buffer.append(name);
		}

		return buffer.toString();
	}

	private void addParentName(StringBuilder buffer) {
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
		buffer.append(parentName).append(NAMESPACE_DELIMITER);
	}

	@Override
	public DataType getDataType(DataTypeManager dataTypeManager) {

		FunctionDefinitionDataType fddt = new FunctionDefinitionDataType(getName());
		fddt.setReturnType(returnType.getDataType(dataTypeManager));

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

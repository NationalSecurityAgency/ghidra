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
package util.demangler;

import java.util.ArrayList;
import java.util.List;

/**
 * A class to represent a demangled function pointer.
 */
public class GenericDemangledFunctionPointer extends GenericDemangledDataType
		implements ParameterReceiver {

	private static final String DEFAULT_NAME_PREFIX = "FuncDef";
	private static final String EMPTY_STRING = "";
	private static final Object NAMESPACE_DELIMITER = "::";
	private static int ID = 0;
	private GenericDemangledDataType returnType;
	protected String callingConvention;// __cdecl, __thiscall, etc.
	private List<GenericDemangledDataType> parameters = new ArrayList<>();

	private boolean isConstPointer;
	private String parentName;
	private boolean isTrailingPointer64;

	/**
	 * Constructs a new demangled function pointer.
	 */
	public GenericDemangledFunctionPointer() {
		super(DEFAULT_NAME_PREFIX + nextID());
	}

	/**
	 * Returns the return type.
	 * @return the return type
	 */
	public GenericDemangledDataType getReturnType() {
		return returnType;
	}

	/**
	 * Sets the return type.
	 * @param returnType the return type
	 */
	public void setReturnType(GenericDemangledDataType returnType) {
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
	 * Adds a parameters to the end of the parameter list for 
	 * this demangled function.
	 * @param parameter the new parameter to add
	 */
	@Override
	public void addParameter(GenericDemangledDataType parameter) {
		parameters.add(parameter);
	}

	/**
	 * Returns a list of the parameters for this demangled functions.
	 * @return a list of the parameters for this demangled functions
	 */
	@Override
	public List<GenericDemangledDataType> getParameters() {
		return new ArrayList<>(parameters);
	}

	@Override
	public GenericDemangledDataType copy() {
		GenericDemangledFunctionPointer copy = new GenericDemangledFunctionPointer();
		copyInto(copy);
		return copy;
	}

	@Override
	public void copyInto(GenericDemangledDataType destination) {
		super.copyInto(destination);

		GenericDemangledFunctionPointer source = this;

		if (destination instanceof GenericDemangledFunctionPointer) {
			GenericDemangledFunctionPointer copySource = source;
			GenericDemangledFunctionPointer copyDestination =
				(GenericDemangledFunctionPointer) destination;

			if (copySource.returnType != null) {
				copyDestination.returnType = copySource.returnType.copy();
			}
			for (GenericDemangledDataType parameter : copySource.parameters) {
				copyDestination.parameters.add(parameter.copy());
			}

			copyDestination.callingConvention = copySource.callingConvention;

			copyDestination.isConstPointer |= copySource.isConstPointer;
		}
	}

	@Override
	public String toSignature() {
		return toSignature(null);
	}

	public String toSignature(String name) {
		StringBuffer buffer = new StringBuffer();

		if (returnType != null) {
			buffer.append(returnType.toSignature()).append(SPACE);
		}

		String s = getConventionPointerNameString(name);
		if (s.contains(" ") || s.isEmpty()) {
			// spaces--add parens
			buffer.append('(').append(s).append(')');
		}
		else {// this allows the '__cdecl' in templates to not have parens
			buffer.append(s);
		}

		buffer.append('(');
		for (int i = 0; i < parameters.size(); ++i) {
			buffer.append(parameters.get(i).toSignature());
			if (i < parameters.size() - 1) {
				buffer.append(',');
			}
		}
		buffer.append(')');

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

		if (isTrailingPointer64) {
			if (buffer.length() > 2) {
				buffer.append(SPACE);
			}
			buffer.append(PTR64);
		}

		return buffer.toString();
	}

	private String getConventionPointerNameString(String name) {
		StringBuilder buffer = new StringBuilder();
		buffer.append(callingConvention == null ? EMPTY_STRING : callingConvention);

		int pointerLevels = getPointerLevels();
		if (pointerLevels > 0) {
			if (callingConvention != null) {
				buffer.append(SPACE);
			}

			addParentName(buffer);

			for (int i = 0; i < pointerLevels; ++i) {
				buffer.append('*');
			}
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
			if (buffer.length() > 2) {
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

	public void setConstPointer() {
		isConstPointer = true;
	}

	public boolean isConstPointer() {
		return isConstPointer;
	}

	public void setParentName(String parentName) {
		this.parentName = parentName;
	}

	public String getParentName() {
		return parentName;
	}

	public void setTrailingPointer64() {
		this.isTrailingPointer64 = true;// TODO get real construct name for this method/field
	}

	public boolean isTrailingPointer64() {
		return isTrailingPointer64;
	}

	public void clearPointer64() {
		this.isPointer64 = false;
	}

	private synchronized static int nextID() {
		return ID++;
	}

	public int getID() {
		return ID;
	}
}

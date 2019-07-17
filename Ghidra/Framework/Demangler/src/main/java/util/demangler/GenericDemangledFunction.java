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

import java.util.*;

/**
 * A class to represent a demangled function.
 */
public class GenericDemangledFunction extends GenericDemangledObject implements ParameterReceiver {

	protected GenericDemangledDataType returnType;
	protected String callingConvention;// __cdecl, __thiscall, etc.
	protected boolean thisPassedOnStack = true;
	protected List<GenericDemangledDataType> parameterList =
		new ArrayList<GenericDemangledDataType>();
	protected GenericDemangledTemplate template;
	protected boolean isOverloadedOperator = false;
	private boolean virtual = false;

	/** Special constructor where it has a templated type before the parameter list */
	private String templatedConstructorType;

	/**
	 * Constructs a new demangled function.
	 * @param name the name of the function
	 */
	public GenericDemangledFunction(String name) throws GenericDemangledException {
		if (name == null) {
			throw new GenericDemangledException(
				"Function name cannot be null; failed to parse mangled name properly");
		}
		this.name = name;
	}

	/**
	 * Sets the function return type.
	 * @param returnType the function return type
	 */
	public void setReturnType(GenericDemangledDataType returnType) {
		this.returnType = returnType;
	}

	/**
	 * Sets the function calling convention. For example, "__cdecl".
	 * @param callingConvention the function calling convention
	 */
	public void setCallingConvention(String callingConvention) {
		this.callingConvention = callingConvention;
	}

	/**
	 * 'this' is passed on the stack or false if in a register
	 *
	 */
	public void setThisPassedOnStack(boolean thisPassedOnStack) {
		this.thisPassedOnStack = thisPassedOnStack;
	}

	public boolean isPassedOnStack() {
		return thisPassedOnStack;
	}

	public void setTemplate(GenericDemangledTemplate template) {
		this.template = template;
	}

	public GenericDemangledTemplate getTemplate() {
		return template;
	}

	public void setVirtual() {
		this.virtual = true;
	}

	public boolean isVirtual() {
		return virtual;
	}

	/**
	 * Sets whether this demangled function represents
	 * an overloaded operator. For example, "operator+()".
	 * @param isOverloadedOperator true if overloaded operator
	 */
	public void setOverloadedOperator(boolean isOverloadedOperator) {
		this.isOverloadedOperator = isOverloadedOperator;
	}

	public boolean isOverloadedOperator() {
		return isOverloadedOperator;
	}

	/**
	 * @see ghidra.app.util.demangler.ParameterReceiver
	 */
	@Override
	public void addParameter(GenericDemangledDataType parameter) {
		parameterList.add(parameter);
	}

	/**
	 * @see ghidra.app.util.demangler.ParameterReceiver
	 */
	@Override
	public List<GenericDemangledDataType> getParameters() {
		return new ArrayList<GenericDemangledDataType>(parameterList);
	}

	/**
	 * Returns the return type or null, if unspecified.
	 * @return the return type or null, if unspecified
	 */
	public GenericDemangledDataType getReturnType() {
		return returnType;
	}

	/**
	 * Returns the calling convention or null, if unspecified.
	 * @return the calling convention or null, if unspecified
	 */
	public String getCallingConvention() {
		return callingConvention;
	}

	/** Special constructor where it has a templated type before the parameter list */
	public void setTemplatedConstructorType(String type) {
		this.templatedConstructorType = type;
	}

	@Override
	public String getSignature(boolean format) {
		StringBuffer buffer = new StringBuffer();

		if (!(returnType instanceof GenericDemangledFunctionPointer)) {
			buffer.append(specialPrefix == null ? "" : specialPrefix + " ");
			buffer.append(visibility == null || "global".equals(visibility) ? "" : visibility + " ");

			if (isStatic()) {
				buffer.append("static ");
			}

			if (virtual) {
				buffer.append("virtual ");
			}
			buffer.append(returnType == null ? "" : returnType.toSignature() + " ");
		}

		buffer.append(callingConvention == null ? "" : callingConvention + " ");
		if (namespace != null) {
			buffer.append(namespace.toNamespace());
		}

		buffer.append(name);
		if (template != null) {
			buffer.append(template.toTemplate());
		}

		if (specialMidfix != null) {
			buffer.append('[').append(specialMidfix).append(']');
		}

		// check for special case of 'conversion operator' where we only want to display '()' and
		// not (void)
		if (name.endsWith("()")) {
			if (name.equals("operator")) {
				buffer.append("()");
			}
		}
		else {
			if (templatedConstructorType != null) {
				buffer.append('<').append(templatedConstructorType).append('>');
			}

			Iterator<GenericDemangledDataType> paramIterator = parameterList.iterator();
			buffer.append('(');
			String pad = format ? pad(buffer.length()) : "";
			if (!paramIterator.hasNext()) {
				buffer.append("void");
			}

			while (paramIterator.hasNext()) {
				buffer.append(paramIterator.next().toSignature());
				if (paramIterator.hasNext()) {
					buffer.append(',');
					if (format) {
						buffer.append('\n');
					}
					buffer.append(pad);
				}
			}
			buffer.append(')');
			buffer.append(storageClass == null ? "" : " " + storageClass);
		}

		if (returnType instanceof GenericDemangledFunctionPointer) {
			GenericDemangledFunctionPointer funcPtr = (GenericDemangledFunctionPointer) returnType;
			String partialSig = funcPtr.toSignature(buffer.toString());
			buffer = new StringBuffer();
			buffer.append(specialPrefix == null ? "" : specialPrefix + " ");
			buffer.append(visibility == null || "global".equals(visibility) ? "" : visibility + " ");
			if (virtual) {
				buffer.append("virtual ");
			}
			buffer.append(partialSig);
		}
		else {
			if (specialSuffix != null) {
				buffer.append(specialSuffix);
			}
		}
		return buffer.toString();
	}

	public String getParameterString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append('(');
		Iterator<GenericDemangledDataType> dditer = parameterList.iterator();
		while (dditer.hasNext()) {
			buffer.append(dditer.next().toSignature());
			if (dditer.hasNext()) {
				buffer.append(',');
			}
		}
		buffer.append(')');
		return buffer.toString();
	}

}

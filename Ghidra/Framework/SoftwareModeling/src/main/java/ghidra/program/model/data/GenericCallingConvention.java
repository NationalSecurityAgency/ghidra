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
package ghidra.program.model.data;

import ghidra.program.model.lang.CompilerSpec;

/**
 * <code>GenericCallingConvention</code> identifies the generic calling convention
 * associated with a specific function definition.  This can be used to help identify
 * the appropriate compiler-specific function prototype (i.e., calling convention).
 * 
 * @deprecated Calling convention name strings should be used instead of this class.
 * {@link CompilerSpec} provides constants for those included in this enumeration and other
 * setter/getter methods exist for using the string form.
 */
public enum GenericCallingConvention {

	/**
	 * The calling convention has not been identified
	 */
	unknown(""),

	/**
	 * A MS Windows specific calling convention applies in which
	 * the called-function is responsible for purging the stack.
	 */
	stdcall(CompilerSpec.CALLING_CONVENTION_stdcall),

	/**
	 * The standard/default calling convention applies
	 * in which the stack is used to pass parameters
	 */
	cdecl(CompilerSpec.CALLING_CONVENTION_cdecl),

	/**
	 * A standard/default calling convention applies
	 * in which only registers are used to pass parameters
	 */
	fastcall(CompilerSpec.CALLING_CONVENTION_fastcall),

	/**
	 * A C++ instance method calling convention applies
	 */
	thiscall(CompilerSpec.CALLING_CONVENTION_thiscall),

	/**
	 * Similar to fastcall but extended vector registers are used
	 */
	vectorcall(CompilerSpec.CALLING_CONVENTION_vectorcall);

	// Append new conventions to the bottom only so that ordinal values will not change!!

	private final String declarationName;

	private GenericCallingConvention(String declarationName) {
		this.declarationName = declarationName;
	}

	public String getDeclarationName() {
		return declarationName;
	}

	@Override
	public String toString() {
		return declarationName;
	}

	/**
	 * Returns the GenericCallingConvention corresponding to the specified
	 * type string or unknown if name is not defined.
	 * @param callingConvention calling convention declaration name (e.g., "__stdcall")
	 * @return GenericCallingConvention or {@link #unknown} if not found.
	 */
	public static GenericCallingConvention getGenericCallingConvention(String callingConvention) {
		for (GenericCallingConvention value : GenericCallingConvention.values()) {
			if (value.name().equalsIgnoreCase(callingConvention)) {
				return value;
			}
		}
		return unknown;
	}

	/**
	 * Returns the GenericCallingConvention corresponding to the specified
	 * ordinal.
	 * @param ordinal generic calling convention ordinal
	 * @return GenericCallingConvention
	 */
	public static GenericCallingConvention get(int ordinal) {
		GenericCallingConvention[] values = GenericCallingConvention.values();
		if (ordinal >= 0 && ordinal < values.length) {
			return values[ordinal];
		}
		return unknown;
	}

}

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
package ghidra.program.util;

import ghidra.program.model.listing.Function;

public class FunctionChangeRecord extends ProgramChangeRecord {
	/**
	 * Specific function changes types for when the ProgramEvent is FUNCTION_CHANGED
	 */
	public enum FunctionChangeType {
		PURGE_CHANGED,			// a function's purge value changed
		INLINE_CHANGED,			// a function's inline status changed
		NO_RETURN_CHANGED,		// a function's no return status changed
		CALL_FIXUP_CHANGED,		// a function's call fixup changed
		RETURN_TYPE_CHANGED,	// a function's return type changed
		PARAMETERS_CHANGED,		// a function's parameters changed
		THUNK_CHANGED,			// a function's thunk status changed
		UNSPECIFIED	   			// a specific function change was not specified
	}

	private FunctionChangeType changeType;

	/**
	 * Constructs a new Function change record.
	 * @param function the function that was changed
	 * @param changeType the specific type of change that was applied to the function
	 */
	public FunctionChangeRecord(Function function, FunctionChangeType changeType) {
		super(ProgramEvent.FUNCTION_CHANGED, function.getEntryPoint(), function.getEntryPoint(),
			function, null, null);
		this.changeType = changeType == null ? FunctionChangeType.UNSPECIFIED : changeType;
	}

	/**
	 * Returns the specific type of function change.
	 * @return the specific type of function change
	 */
	public FunctionChangeType getSpecificChangeType() {
		return changeType;
	}

	/**
	 * Returns the function that was changed.
	 * @return the function that was changed
	 */
	public Function getFunction() {
		return (Function) getObject();
	}

	/**
	 * Returns true if the specific change was related to the function signature.
	 * @return true if the specific change was related to the function signature
	 */
	public boolean isFunctionSignatureChange() {
		return changeType == FunctionChangeType.PARAMETERS_CHANGED ||
			changeType == FunctionChangeType.RETURN_TYPE_CHANGED;
	}

	/**
	 * Returns true if the specific change was to one of the function's modifier properties.
	 * @return true if the specific change was to one of the function's modifier properties
	 */
	public boolean isFunctionModifierChange() {
		// @formatter:off
		return changeType == FunctionChangeType.THUNK_CHANGED || 
			   changeType == FunctionChangeType.INLINE_CHANGED ||
			   changeType == FunctionChangeType.NO_RETURN_CHANGED || 
			   changeType == FunctionChangeType.CALL_FIXUP_CHANGED ||
			   changeType == FunctionChangeType.PURGE_CHANGED;
		// @formatter:on
	}
}

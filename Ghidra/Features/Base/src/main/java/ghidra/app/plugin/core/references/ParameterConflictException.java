/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.references;

import ghidra.util.NumericUtilities;

/**
 * <code>ParameterConflictException</code> indicates that the 
 * stack offset conflicts with an existing function parameter.
 */
class ParameterConflictException extends Exception {
	
	ParameterConflictException(String paramName, int stackOffset) {
		super("New parameter conflicts with '" + paramName + "' at stack offset " + 
				NumericUtilities.toSignedHexString(stackOffset));
	}

}

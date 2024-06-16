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
package ghidra.features.bsim.gui.search.results;

import ghidra.util.exception.UsrException;

/**
 * An exception that can be thrown if an error is encountered while trying to compare two functions
 * or apply information between them.
 */
public class FunctionComparisonException extends UsrException {

	/**
	 * Constructor
	 * @param msg a message indicating details of the error.
	 */
	public FunctionComparisonException(String msg) {
		super(msg);
	}

	/**
	 * Constructor
	 * @param msg a message indicating details of the error.
	 * @param cause another exception indicating the cause that led to this error exception.
	 */
	public FunctionComparisonException(String msg, Throwable cause) {
		super(msg, cause);
	}

}

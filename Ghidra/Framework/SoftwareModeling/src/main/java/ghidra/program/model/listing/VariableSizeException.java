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
package ghidra.program.model.listing;

import ghidra.util.exception.InvalidInputException;

/**
 * <code>VariableSizeException</code> is thrown when a variable
 * data-type exceeds storage constraints.
 */
public class VariableSizeException extends InvalidInputException {

	private static final long serialVersionUID = 1L;
	
	private final boolean canForce;

	/**
	 * Constructor.
	 * The canForce value is assumed to be false.
	 * @param msg message text
	 */
	public VariableSizeException(String msg) {
		this(msg, false);
	}
	
	/**
	 * Constructor.
	 * @param msg message text
	 * @param canForce if true conveys to the user that the operation may
	 * be successful if forced.
	 */
	public VariableSizeException(String msg, boolean canForce) {
		super(msg);
		this.canForce = canForce;
	}
	
	/**
	 * Returns true if the operation could be successful if forced.
	 */
	public boolean canForce() {
		return canForce;
	}

}

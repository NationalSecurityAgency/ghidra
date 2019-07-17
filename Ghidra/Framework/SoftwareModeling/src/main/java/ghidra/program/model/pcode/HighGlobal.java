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
package ghidra.program.model.pcode;

import ghidra.program.model.data.DataType;
import ghidra.util.exception.InvalidInputException;

/**
 * 
 *
 * All references (per function) to a single global variable
 */
public class HighGlobal extends HighVariable {

	/**
	 * @param name name of global variable
	 * @param type data type of variable
	 * @param vn global variable storage
	 * @param func the associated high function
	 * @throws InvalidInputException 
	 */
	public HighGlobal(String name, DataType type, Varnode vn, Varnode[] inst, HighFunction func)
			throws InvalidInputException {
		super(name, type, vn, inst, func);
	}

}

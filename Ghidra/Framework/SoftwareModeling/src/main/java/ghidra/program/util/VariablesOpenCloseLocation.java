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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * ProgramLocation that represents the cursor being on the variables open/close widget
 */
public class VariablesOpenCloseLocation extends CodeUnitLocation {
	/**
	 * Constructor
	 * 
	 * @param program the program of the location
	 * @param addr address of the location
	 */
	public VariablesOpenCloseLocation(Program program, Address addr) {
		super(program, addr, null, 0, 0, 0);
	}

	public VariablesOpenCloseLocation() {

	}
}

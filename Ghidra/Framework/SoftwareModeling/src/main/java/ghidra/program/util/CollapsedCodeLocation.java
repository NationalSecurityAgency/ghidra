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
 * <CODE>CollapsedCodeLocation</CODE> is program location generated when the cursor is on a field
 * representing code from a collapsed function.
 */
public class CollapsedCodeLocation extends ProgramLocation {

	/**
	  * Create a new DividerLocation.
	  * 
	  * @param program the program of the location
	  * @param addr address of bookmark
	  * by its hierarchy names; this parameter may be null
	  */
	public CollapsedCodeLocation(Program program, Address addr) {
		super(program, addr, addr, null, null, 0, 0, 0);
	}

	/**
	 * Default constructor needed for restoring
	 * a program location from XML
	 */
	public CollapsedCodeLocation() {
	}

}

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
package ghidra.examples;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.CodeUnitLocation;

/**
 * The <CODE>EntropyFieldLocation</CODE> class contains specific location information
 * within the OPERAND field of a CodeUnitLocation object.
 */
public class EntropyFieldLocation extends CodeUnitLocation {

	/**
	 * Construct a new EntropyFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param addr address of the location; should not be null
	 * @param charOffset character offset
	 */
	public EntropyFieldLocation(Program program, Address addr, int charOffset) {
		super(program, addr, 0, 0, charOffset);
	}

	/**
	* Default constructor needed for restoring
	* an entropy field location from XML.
	*/
	public EntropyFieldLocation() {
	}

}

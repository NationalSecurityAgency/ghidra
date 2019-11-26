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
 * The <CODE>SpaceFieldLocation</CODE> class contains specific location information
 * within the Space field of a CodeUnitLocation object.
 */
public class SpaceFieldLocation extends CodeUnitLocation {

	/**
	 * Construct a new SpaceFieldLocation.
	 * 
	 * @param program the program of the location
	 * @param addr the address of the codeunit.
	 * @param componentPath the componentPath of the codeUnit
	 * @param row the line of the location
	 */
	public SpaceFieldLocation(Program program, Address addr, GroupPath path, int[] componentPath,
			int row) {

		super(program, addr, componentPath, row, 0, 0);
	}

	/**
	 * Default constructor needed for restoring
	 * a space field location from XML.
	 */
	public SpaceFieldLocation() {
	}

}

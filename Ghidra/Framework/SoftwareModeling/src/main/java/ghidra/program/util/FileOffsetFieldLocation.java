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
 * Provides specific information about a program location within the File Offset field
 */
public class FileOffsetFieldLocation extends CodeUnitLocation {

	/**
	 * Creates a new {@link FileOffsetFieldLocation} for the given address
	 * 
	 * @param program the program
	 * @param addr the address of the byte for this location
	 * @param componentPath the path to data, or null
	 * @param charOffset the position into the string representation indicating the exact
	 *   position within the field
	 */
	public FileOffsetFieldLocation(Program program, Address addr, int[] componentPath,
			int charOffset) {
		super(program, addr, componentPath, 0, 0, charOffset);
	}


	/**
	 * Default constructor needed for restoring the field location from XML
	 */
	public FileOffsetFieldLocation() {
	}
}

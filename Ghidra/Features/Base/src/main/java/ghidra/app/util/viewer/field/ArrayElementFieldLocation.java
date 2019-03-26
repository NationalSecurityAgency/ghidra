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
package ghidra.app.util.viewer.field;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.OperandFieldLocation;

public class ArrayElementFieldLocation extends OperandFieldLocation {

	/**
	 * Creates an ArrayElementFieldLocation
	 * @param program the program
	 * @param address the address of the location
	 * @param componentPath the data component path
	 * @param displayValue the text being displayed in the text.
	 * @param elementIndex the element of the array on the line.
	 * @param charOffset the character position within the text.
	 */
	public ArrayElementFieldLocation(Program program, Address address, int[] componentPath,
			String displayValue, int elementIndex, int charOffset) {

		super(program, address, componentPath, null, displayValue, elementIndex, charOffset);
	}

	/**
	 * Default constructor needed for restoring from XML.
	 */
	public ArrayElementFieldLocation() {
		// for restoring from XML
	}

	public int getElementIndexOnLine(Data firstDataOnLine) {
		int addressOffset = (int) addr.subtract(firstDataOnLine.getMinAddress());
		return addressOffset / firstDataOnLine.getDataType().getLength();
	}
}

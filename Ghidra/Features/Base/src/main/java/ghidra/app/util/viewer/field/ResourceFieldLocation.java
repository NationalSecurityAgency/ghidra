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
import ghidra.program.model.data.DataImage;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * A {@link ProgramLocation} of an item that is a Resource 
 * embedded in a binary (ie. a embedded graphic image)
 */
public class ResourceFieldLocation extends OperandFieldLocation {

	/**
	 * Cached here because users will probably need to query its details during
	 * action enablement
	 */
	private Data data;

	/**
	 * Creates an ResourceFieldLocation
	 * 
	 * @param program the program
	 * @param address the address of the location
	 * @param componentPath the data component path
	 * @param displayValue the text being displayed in the text.
	 * @param opIndex the index of the operand at this location.
	 * @param characterOffset the character position from the beginning of the operand.
	 * @param data Data instance at the specified address / component path
	 */
	public ResourceFieldLocation(Program program, Address address, int[] componentPath,
			String displayValue, int opIndex, int characterOffset, Data data) {

		super(program, address, componentPath, null, displayValue, opIndex, characterOffset);
		
		this.data = data;
	}

	/**
	 * Default constructor needed for restoring from XML.
	 */
	public ResourceFieldLocation() {
		// for restoring from XML
	}

	/**
	 * Returns the resource's Data instance.
	 * 
	 * @return the resource's Data instance 
	 */
	public Data getResourceData() {
		if (data == null) {
			data = DataUtilities.getDataAtLocation(this);
		}
		return data;
	}

	/**
	 * Returns true if this resource is a {@link DataImage}.
	 * 
	 * @return true if this resource is a {@link DataImage}
	 */
	public boolean isDataImageResource() {
		getResourceData(); // side effect to init data if null after deserialization
		return data != null && data.getValue() instanceof DataImage;
	}

}

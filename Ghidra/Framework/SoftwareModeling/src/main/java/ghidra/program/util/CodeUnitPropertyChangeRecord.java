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

/**
 * Change record generated when a property on a code unit changes.
 */
public class CodeUnitPropertyChangeRecord extends ProgramChangeRecord {
	private String propertyName;

	/**
	 * Constructor
	 * @param type the program event type
	 * @param propertyName the name of the code unit property
	 * @param start the start address of the effected range
	 * @param end the end address of the effected range
	 * @param oldValue the old property value
	 * @param newValue the new property value
	 */
	private CodeUnitPropertyChangeRecord(ProgramEvent type, String propertyName, Address start,
			Address end, Object oldValue, Object newValue) {
		super(type, start, end, null, oldValue, newValue);
		this.propertyName = propertyName;
	}

	/**
	 * Constructor for a property change at an address
	 * @param type the program event type
	 * @param propertyName the name of the code unit property
	 * @param address the address of the of the property that was changed.
	 * @param oldValue the old property value
	 * @param newValue the new property value
	 */
	public CodeUnitPropertyChangeRecord(ProgramEvent type, String propertyName, Address address,
			Object oldValue, Object newValue) {
		this(type, propertyName, address, address, oldValue, newValue);
	}

	/**
	 * Constructor for events that affect a range of values
	 * @param type the program event type
	 * @param propertyName the name of the code unit property
	 * @param start the start address of the range affected
	 * @param end the end address of the range affected
	 */
	public CodeUnitPropertyChangeRecord(ProgramEvent type, String propertyName, Address start,
			Address end) {
		this(type, propertyName, start, end, null, null);
	}

	/**
	 * Get the name of the property being changed.
	 * @return the name of the property being changed
	 */
	public String getPropertyName() {
		return propertyName;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder(super.toString());
		builder.append(", property = " + propertyName);
		return builder.toString();
	}
}

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

import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.program.model.address.Address;

public class CodeUnitUserDataChangeRecord extends DomainObjectChangeRecord {

	private String propertyName;
	private Address address;

	/**
	 * Constructor
	 * @param propertyName name of the property
	 * @param codeUnitAddr address of the code unit
	 * @param oldValue old value
	 * @param newValue new value
	 */
	public CodeUnitUserDataChangeRecord(String propertyName, Address codeUnitAddr, Object oldValue,
			Object newValue) {
		super(ProgramEvent.CODE_UNIT_USER_DATA_CHANGED, oldValue, newValue);
		this.propertyName = propertyName;
		address = codeUnitAddr;
	}

	/**
	 * Get the name of the property being changed.
	 * @return the name of the property being changed
	 */
	public String getPropertyName() {
		return propertyName;
	}

	/**
	 * Get the address of the code unit for this property change.
	 * @return the address of the code unit for this property change
	 */
	public Address getAddress() {
		return address;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder(super.toString());
		builder.append(", property = " + propertyName);
		if (address != null) {
			builder.append(", address = ");
			builder.append(address);
		}
		return builder.toString();
	}

}

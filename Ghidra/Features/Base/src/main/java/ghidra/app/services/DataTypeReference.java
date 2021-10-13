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
package ghidra.app.services;

import ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;

/**
 * A container class to hold information about a location that references a {@link DataType}.
 */
public class DataTypeReference {

	private DataType dataType;
	private String fieldName;
	private Function function;
	private Address address;

	/** A preview of how the reference was used */
	private LocationReferenceContext context;

	public DataTypeReference(DataType dataType, String fieldName, Function function,
			Address address, LocationReferenceContext context) {
		this.dataType = dataType;
		this.fieldName = fieldName;
		this.function = function;
		this.address = address;
		this.context = context;
	}

	public DataType getDataType() {
		return dataType;
	}

	public Function getFunction() {
		return function;
	}

	public Address getAddress() {
		return address;
	}

	public LocationReferenceContext getContext() {
		return context;
	}

	@Override
	public String toString() {
		String fieldNameText = fieldName == null ? "" : "\tfieldName: " + fieldName + "\n";

		//@formatter:off
		return "{\n" +
			"\tdataType: " + dataType.getName() + "\n" +
			fieldNameText +
			"\tfunction: " + function.getName() + "\n" +
			"\taddress: " + address + "\n" +
			"\tcontext: " + context + "\n" +
		"}";
		//@formatter:on
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((address == null) ? 0 : address.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		// Note: I don't think we can have more than one access at a given address
		DataTypeReference other = (DataTypeReference) obj;
		if (address == null) {
			if (other.address != null) {
				return false;
			}
		}
		else if (!address.equals(other.address)) {
			return false;
		}
		return true;
	}
}

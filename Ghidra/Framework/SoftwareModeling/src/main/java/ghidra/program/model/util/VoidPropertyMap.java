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
package ghidra.program.model.util;

import ghidra.program.model.address.Address;

/**
 * Property manager that deals with properties that are of
 * "void" type, which is a marker for whether a property exists.
 * Object values returned are either {@link Boolean#TRUE} or null.
 */
public interface VoidPropertyMap extends PropertyMap<Boolean> {
	
	@Override
	public default Class<Boolean> getValueClass() {
		return Boolean.class;
	}

	/**
	 * Mark the specified address as having a property
	 * @param addr address for the property
	 */
	public void add(Address addr);

	/**
	 * Apply property value to specified address.
	 * @param addr property address
	 * @param value boolean value (null or false will remove property value)
	 * @throws IllegalArgumentException if value specified is not a Boolean or null
	 */
	@Override
	public default void add(Address addr, Object value) {
		if (value == null) {
			remove(addr);
			return;
		}
		if (!(value instanceof Boolean)) {
			throw new IllegalArgumentException("Boolean value required");
		}
		Boolean b = (Boolean) value;
		if (!b) {
			remove(addr);
		}
		else {
			add(addr);
		}
	}

}

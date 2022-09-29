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
import ghidra.util.Saveable;

/**
 * Property manager that deals with properties that are of
 * Object type.
 * @param <T> {@link Saveable} implementation type
 */
public interface ObjectPropertyMap<T extends Saveable> extends PropertyMap<T> {

	/**
	 * Add an object value at the specified address.
	 * @param addr address for the property
	 * @param value value of the property
	 * @throws IllegalArgumentException if value is type is inconsistent with map
	 */
	public void add(Address addr, T value) throws IllegalArgumentException;

	@SuppressWarnings("unchecked")
	@Override
	public default void add(Address addr, Object value) {
		if (value == null) {
			remove(addr);
			return;
		}
		Class<? extends Saveable> saveableObjectClass = getValueClass();
		if (!saveableObjectClass.isAssignableFrom(value.getClass())) {
			throw new IllegalArgumentException("value is not " + saveableObjectClass.getName());
		}
		((ObjectPropertyMap<Saveable>) this).add(addr, (Saveable) value);
	}
}

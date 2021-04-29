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
package ghidra.trace.model.property;

import java.util.Map;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.util.TypeMismatchException;
import ghidra.trace.model.map.TracePropertyMap;
import ghidra.util.exception.DuplicateNameException;

public interface TraceAddressPropertyManager {
	/**
	 * Create a property map with the given name having the given type
	 * 
	 * @param name the name
	 * @param valueClass the type of values
	 * @return the new property map
	 * @throws DuplicateNameException if a map of the given name already exists
	 */
	<T> TracePropertyMap<T> createPropertyMap(String name, Class<T> valueClass)
			throws DuplicateNameException;

	/**
	 * Get the property map with the given name, if it has the given type
	 * 
	 * @param name the name
	 * @param valueClass the expected type of values
	 * @return the property map, or null if it does not exist
	 * @throws TypeMismatchException if it exists but does not have the expected type
	 */
	<T> TracePropertyMap<T> getPropertyMap(String name, Class<T> valueClass);

	/**
	 * Get the property map with the given name, creating it if necessary, of the given type
	 * 
	 * @param name the name
	 * @param valueClass the expected type of values
	 * @return the (possibly new) property map
	 */
	<T> TracePropertyMap<T> getOrCreatePropertyMap(String name, Class<T> valueClass);

	/**
	 * Get the property map with the given name, if its type extends the given type
	 * 
	 * This implies that the returned map's {@link TracePropertyMap#get(long, Address)} method will
	 * return values which can be assigned to variables of the given type. Its
	 * {@link TracePropertyMap#set(Range, Address, Object)} method, however, will not accept any
	 * value parameter, as it will have a wildcard-extends type.
	 * 
	 * @param name the name
	 * @param valueClass the expected type of values to get
	 * @return the property map suitable for getting values of the given type
	 */
	<T> TracePropertyMap<? extends T> getPropertyGetter(String name, Class<T> valueClass);

	/**
	 * Get the property map with the given name, if its type is a super-type of the given type
	 * 
	 * This implies that the returned map's {@link TracePropertyMap#set(Range, Address, Object)}
	 * method will accept values from variables of the given type. Its
	 * {@link TracePropertyMap#get(long, Address)} method, however, will return {@link Object}, as
	 * it will have a wildcard-super type.
	 * 
	 * @param name the name
	 * @param valueClass the expect3ed type of values to set
	 * @return the property map suitable for setting values of the given type
	 */
	<T> TracePropertyMap<? super T> getOrCreatePropertySetter(String name, Class<T> valueClass);

	/**
	 * Get the property map with the given name.
	 * 
	 * Note that no type checking is performed (there is no {@code valueClass} parameter, after all.
	 * Thus, the returned map is suitable only for clearing and querying where the property is
	 * present. The caller may perform run-time type checking via the
	 * {@link TracePropertyMap#getValueClass()} method.
	 * 
	 * @param name the name
	 * @return the property map
	 */
	TracePropertyMap<?> getPropertyMap(String name);

	/**
	 * Get an unmodifiable view of all the defined properties
	 * 
	 * @return the map view of names to property maps
	 */
	Map<String, TracePropertyMap<?>> getAllProperties();
}

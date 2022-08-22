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

import ghidra.program.model.util.TypeMismatchException;
import ghidra.util.Saveable;
import ghidra.util.exception.DuplicateNameException;

/**
 * The manager for user properties of a trace
 * 
 * <p>
 * Clients may create property maps of various value types. Each map is named, also considered the
 * "property name," and can be retrieve by that name.
 */
public interface TraceAddressPropertyManager {
	/**
	 * Create a property map with the given name having the given type
	 * 
	 * <p>
	 * The following types are supported for valueClass:
	 * <ul>
	 * <li>{@link Integer}</li>
	 * <li>{@link Long}</li>
	 * <li>{@link String}</li>
	 * <li>{@link Void}: presence or absence of entry satisfies "boolean" use case</li>
	 * <li>{@code ? extends }{@link Saveable}</li>
	 * </ul>
	 * 
	 * <p>
	 * Note that for maps of user-defined {@link Saveable} type, only the specified type is accepted
	 * by the map. Attempting to save an extension of that type may lead to undefined behavior,
	 * esp., if it attempts to save additional fields. When the value is restored, it will have the
	 * type given in {@code valueClass}, not the extended type.
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
	 * Get the property map with the given name, if its values extend the given type
	 * 
	 * @param name the name
	 * @param valueClass the expected type of values
	 * @return the property map, or null if it does not exist
	 * @throws TypeMismatchException if it exists but does not have the expected type
	 */
	<T> TracePropertyMap<? extends T> getPropertyMapExtends(String name, Class<T> valueClass);

	/**
	 * Get the property map with the given name, creating it if necessary, of the given type
	 * 
	 * @see #createPropertyMap(String, Class)
	 * @param name the name
	 * @param valueClass the expected type of values
	 * @return the (possibly new) property map
	 */
	<T> TracePropertyMap<T> getOrCreatePropertyMap(String name, Class<T> valueClass);

	/**
	 * Get the property map with the given name, creating it if necessary, of the given type
	 * 
	 * <p>
	 * If the map already exists, then its values' type must be a super type of that given.
	 * 
	 * @see #getOrCreatePropertyMap(String, Class)
	 * @param name the name
	 * @param valueClass the expected type of values
	 * @return the (possibly new) property map
	 */
	<T> TracePropertyMap<? super T> getOrCreatePropertyMapSuper(String name, Class<T> valueClass);

	/**
	 * Get the property map with the given name.
	 * 
	 * <p>
	 * Note that no type checking is performed (there is no {@code valueClass} parameter). Thus, the
	 * returned map is suitable only for clearing and querying where the property is present. The
	 * caller may perform run-time type checking via the
	 * {@link TracePropertyMapOperations#getValueClass()} method.
	 * 
	 * @param name the name
	 * @return the property map
	 */
	TracePropertyMap<?> getPropertyMap(String name);

	/**
	 * Get a copy of all the defined properties
	 * 
	 * @return the set of names
	 */
	Map<String, TracePropertyMap<?>> getAllProperties();
}

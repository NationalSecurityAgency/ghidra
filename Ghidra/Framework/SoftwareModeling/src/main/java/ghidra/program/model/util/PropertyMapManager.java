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

import java.util.Iterator;

import ghidra.program.model.address.Address;
import ghidra.util.Saveable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.map.TypeMismatchException;
import ghidra.util.task.TaskMonitor;

/**
 *
 * Interface for managing a set of PropertyManagers.
 * 
 */
public interface PropertyMapManager {
	/**
	 * Creates a new IntPropertyMap with the given name.
	 * @param propertyName the name for the new property.
	 * @return newly created integer object map
	 * @exception DuplicateNameException thrown if a PropertyMap already
	 * exists with that name. 
	 */
	public IntPropertyMap createIntPropertyMap(String propertyName) throws DuplicateNameException;

	/**
	 * Creates a new LongPropertyMap with the given name.
	 * @param propertyName the name for the new property.
	 * @return newly created long object map
	 * @exception DuplicateNameException thrown if a PropertyMap already
	 * exists with that name. 
	 */
	public LongPropertyMap createLongPropertyMap(String propertyName) throws DuplicateNameException;

	/**
	 * Creates a new StringPropertyMap with the given name.
	 * @param propertyName the name for the new property.
	 * @return newly created string object map
	 * @exception DuplicateNameException thrown if a PropertyMap already
	 * exists with that name.
	 */
	public StringPropertyMap createStringPropertyMap(String propertyName)
			throws DuplicateNameException;

	/**
	 * Creates a new ObjectPropertyMap with the given name.
	 * @param <T> {@link Saveable} property value type
	 * @param propertyName the name for the new property.
	 * @param objectClass {@link Saveable} implementation class
	 * @return newly created {@link Saveable} object map
	 * @exception DuplicateNameException thrown if a PropertyMap already
	 * exists with that name.
	 */
	public <T extends Saveable> ObjectPropertyMap<T> createObjectPropertyMap(String propertyName,
			Class<T> objectClass) throws DuplicateNameException;

	/**
	 * Creates a new VoidPropertyMap with the given name.
	 * @param propertyName the name for the new property.
	 * @return newly created void map
	 * @exception DuplicateNameException thrown if a PropertyMap already
	 * exists with that name.
	 */
	public VoidPropertyMap createVoidPropertyMap(String propertyName) throws DuplicateNameException;

	/**
	 * Returns the PropertyMap with the given name or null if no PropertyMap
	 * exists with that name.
	 * @return existing map or null if not found
	 * @param propertyName the name of the property to retrieve.
	 */
	public PropertyMap<?> getPropertyMap(String propertyName);

	/**
	 * Returns the IntPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @return existing map or null if not found
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an IntPropertyMap.
	 */
	public IntPropertyMap getIntPropertyMap(String propertyName);

	/**
	 * Returns the LongPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @return existing map or null if not found
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an LongPropertyMap.
	 */
	public LongPropertyMap getLongPropertyMap(String propertyName);

	/**
	 * Returns the StringPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @return existing map or null if not found
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not a StringPropertyMap.
	 */
	public StringPropertyMap getStringPropertyMap(String propertyName);

	/**
	 * Returns the ObjectPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @return existing map or null if not found
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an ObjectPropertyMap.
	 */
	public ObjectPropertyMap<? extends Saveable> getObjectPropertyMap(String propertyName);

	/**
	 * Returns the VoidPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @return existing map or null if not found
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not a VoidPropertyMap.
	 */
	public VoidPropertyMap getVoidPropertyMap(String propertyName);

	/**
	 * Removes the PropertyMap with the given name.
	 * @param propertyName the name of the property to remove.
	 * @return true if a PropertyMap with that name was found (and removed)
	 */
	public boolean removePropertyMap(String propertyName);

	/**
	 * Returns an iterator over the names of all existing PropertyMaps.
	 */
	public Iterator<String> propertyManagers();

	/**
	 * Removes any property at the given address from all defined 
	 * PropertyMaps.
	 * @param addr the address at which to remove all property values.
	 */
	public void removeAll(Address addr);

	/**
	 * Removes all properties in the given range from all user 
	 * defined PropertyMaps.
	 * @param startAddr the first address in the range of addresses where 
	 * propertie values are to be removed.
	 * @param endAddr the last address in the range of addresses where 
	 * propertie values are to be removed.
	 * @param monitor monitors progress
	 * @throws CancelledException if the user cancelled the operation.
	 */
	public void removeAll(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException;

}

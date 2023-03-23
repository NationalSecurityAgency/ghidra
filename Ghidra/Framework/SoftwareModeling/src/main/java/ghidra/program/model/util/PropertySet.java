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

import ghidra.util.Saveable;
import ghidra.util.exception.NoValueException;
import ghidra.util.map.TypeMismatchException;

public interface PropertySet {

	/**
	 * Set the named property with the given {@link Saveable} value.
	 * @param name the name of the property.
	 * @param value value to be stored.
	 * @param <T> {@link Saveable} implementation
	 * @throws IllegalArgumentException if value type is inconsistent with named map
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an ObjectPropertyMap.
	 */
	public <T extends Saveable> void setProperty(String name, T value)
			throws IllegalArgumentException;

	/**
	 * Set the named string property with the given value.
	 * @param name the name of the property.
	 * @param value value to be stored.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not a StringPropertyMap.
	 */
	public void setProperty(String name, String value);

	/**
	 * Set the named integer property with the given value.
	 * @param name the name of the property.
	 * @param value value to be stored.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an IntPropertyMap.
	 */
	public void setProperty(String name, int value);

	/**
	 * Set the named property.  This method is used for "void" properites. The
	 * property is either set or not set - there is no value
	 * @param name the name of the property.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not a VoidPropertyMap.
	 */
	public void setProperty(String name);

	/**
	 * Get the object property for name; returns null if
	 * there is no name property for this code unit.
	 * @param name the name of the property
	 * @return {@link Saveable} property value, with map-specific implementation class, or null.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an ObjectPropertyMap.
	 */
	public Saveable getObjectProperty(String name);

	/**
	 * Get the string property for name; returns null if
	 * there is no name property for this code unit.
	 * @param name the name of the property
	 * @return string property value or null
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an StringPropertyMap.
	 */
	public String getStringProperty(String name);

	/**
	 * Get the int property for name.
	 * @param name the name of the property
	 * @return integer property value property has been set
	 * @throws NoValueException if there is not name property
	 * for this code unit
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an IntPropertyMap.
	 */
	public int getIntProperty(String name) throws NoValueException;

	/**
	 * Returns true if the codeunit has the given property defined.
	 * This method works for all property map types.
	 * @param name the name of the property
	 * @return true if property has been set, else false
	 */
	public boolean hasProperty(String name);

	/**
	 * Returns whether this code unit is marked as having the
	 * name property.
	 * @param name the name of the property
	 * @return true if property has been set, else false
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an VoidPropertyMap.
	 */
	boolean getVoidProperty(String name);

	/**
	 * Get an iterator over the property names which have values applied.
	 * @return iterator of all property map names which have values applied
	 */
	public Iterator<String> propertyNames();

	/**
	 * Remove the property value associated with the given name .
	 * @param name the name of the property
	 */
	public void removeProperty(String name);
}

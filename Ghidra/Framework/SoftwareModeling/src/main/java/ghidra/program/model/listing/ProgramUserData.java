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
package ghidra.program.model.listing;

import java.util.List;
import java.util.Set;

import db.Transaction;
import ghidra.framework.model.UserData;
import ghidra.framework.options.Options;
import ghidra.program.model.util.*;
import ghidra.util.Saveable;
import ghidra.util.exception.PropertyTypeMismatchException;

public interface ProgramUserData extends UserData {

	/**
	 * Open new transaction.  This should generally be done with a try-with-resources block:
	 * <pre>
	 * try (Transaction tx = pud.openTransaction(description)) {
	 * 	// ... Do something
	 * }
	 * </pre>
	 * 
	 * @return transaction object
	 * @throws IllegalStateException if this {@link ProgramUserData} has already been closed.
	 */
	public Transaction openTransaction();

	/**
	 * Start a transaction prior to changing any properties
	 * @return transaction ID needed for endTransaction
	 */
	public int startTransaction();

	/**
	 * End a previously started transaction
	 * @param transactionID the id of the transaction to close
	 */
	public void endTransaction(int transactionID);

	/**
	 * Get a address-based String property map
	 * @param owner name of property owner (e.g., plugin name)
	 * @param propertyName the name of property map
	 * @param create creates the property map if it does not exist
	 * @return the property map for the given name
	 * @throws PropertyTypeMismatchException if a conflicting map definition was found
	 */
	public StringPropertyMap getStringProperty(String owner, String propertyName, boolean create)
			throws PropertyTypeMismatchException;

	/**
	 * Get a address-based Long property map
	 * @param owner name of property owner (e.g., plugin name)
	 * @param propertyName the name of property map
	 * @param create creates the property map if it does not exist
	 * @return property map
	 * @throws PropertyTypeMismatchException if a conflicting map definition was found
	 */
	public LongPropertyMap getLongProperty(String owner, String propertyName, boolean create)
			throws PropertyTypeMismatchException;

	/**
	 * Get a address-based Integer property map
	 * @param owner name of property owner (e.g., plugin name)
	 * @param propertyName the name of property map
	 * @param create creates the property map if it does not exist
	 * @return property map
	 * @throws PropertyTypeMismatchException if a conflicting map definition was found
	 */
	public IntPropertyMap getIntProperty(String owner, String propertyName, boolean create)
			throws PropertyTypeMismatchException;

	/**
	 * Get a address-based Boolean property map
	 * @param owner name of property owner (e.g., plugin name)
	 * @param propertyName the name of property map
	 * @param create creates the property map if it does not exist
	 * @return property map
	 * @throws PropertyTypeMismatchException if a conflicting map definition was found
	 */
	public VoidPropertyMap getBooleanProperty(String owner, String propertyName, boolean create)
			throws PropertyTypeMismatchException;

	/**
	 * Get a address-based Saveable-object property map
	 * @param owner name of property owner (e.g., plugin name)
	 * @param propertyName the name of property map
	 * @param saveableObjectClass the class type for the object property map
	 * @param create creates the property map if it does not exist
	 * @param <T> {@link Saveable} property value type
	 * @return property map
	 * @throws PropertyTypeMismatchException if a conflicting map definition was found
	 */
	public <T extends Saveable> ObjectPropertyMap<T> getObjectProperty(String owner,
			String propertyName, Class<T> saveableObjectClass, boolean create);

	/**
	 * Get all property maps associated with a specific owner.
	 * @param owner name of property owner (e.g., plugin name)
	 * @return list of property maps
	 */
	public List<PropertyMap<?>> getProperties(String owner);

	/**
	 * Returns list of all property owners for which property maps have been defined.
	 * @return list of all property owners for which property maps have been defined.
	 */
	public List<String> getPropertyOwners();

	/**
	 * Returns all names of all the Options objects store in the user data
	 * 
	 * @return all names of all the Options objects store in the user data
	 */
	public List<String> getOptionsNames();

	/**
	 * Get the Options for the given optionsName
	 * @param optionsName the name of the options options to retrieve
	 * @return The options for the given name
	 */
	public Options getOptions(String optionsName);

	/**
	 * Sets the given String property
	 * @param propertyName the name of the property
	 * @param value the value of the property
	 */
	public void setStringProperty(String propertyName, String value);

	/**
	 * Gets the value for the given property name
	 * @param propertyName the name of the string property to retrieve
	 * @param defaultValue the value to return if there is no saved value for the given name
	 * @return the value for the given property name
	 */
	public String getStringProperty(String propertyName, String defaultValue);

	/**
	 * Removes the String property with the given name;
	 * @param propertyName the name of the property to remove;
	 * @return returns the value of the property that was removed or null if the property doesn't
	 * exist
	 */
	public String removeStringProperty(String propertyName);

	/**
	 * Returns a set of all String properties that have been set on this ProgramUserData object
	 * @return a set of all String properties that have been set on this ProgramUserData object
	 */
	public Set<String> getStringPropertyNames();
}

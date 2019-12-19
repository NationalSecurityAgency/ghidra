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

import ghidra.framework.model.UserData;
import ghidra.framework.options.Options;
import ghidra.program.model.util.*;
import ghidra.util.Saveable;
import ghidra.util.exception.PropertyTypeMismatchException;

public interface ProgramUserData extends UserData {

	/**
	 * Start a transaction prior to changing any properties
	 * @return transaction ID needed for endTransaction
	 */
	public int startTransaction();

	/**
	 * End a previously started transaction
	 * @param transactionID
	 */
	public void endTransaction(int transactionID);

	/**
	 * Get a address-based String property map
	 * @param owner name of property owner (e.g., plugin name)
	 * @param propertyName
	 * @param create creates the property map if it does not exist
	 * @return property map
	 * @throws PropertyTypeMismatchException if a conflicting map definition was found
	 */
	public StringPropertyMap getStringProperty(String owner, String propertyName, boolean create)
			throws PropertyTypeMismatchException;

	/**
	 * Get a address-based Long property map
	 * @param owner name of property owner (e.g., plugin name)
	 * @param propertyName
	 * @param create creates the property map if it does not exist
	 * @return property map
	 * @throws PropertyTypeMismatchException if a conflicting map definition was found
	 */
	public LongPropertyMap getLongProperty(String owner, String propertyName, boolean create)
			throws PropertyTypeMismatchException;

	/**
	 * Get a address-based Integer property map
	 * @param owner name of property owner (e.g., plugin name)
	 * @param propertyName
	 * @param create creates the property map if it does not exist
	 * @return property map
	 * @throws PropertyTypeMismatchException if a conflicting map definition was found
	 */
	public IntPropertyMap getIntProperty(String owner, String propertyName, boolean create)
			throws PropertyTypeMismatchException;

	/**
	 * Get a address-based Boolean property map
	 * @param owner name of property owner (e.g., plugin name)
	 * @param propertyName
	 * @param create creates the property map if it does not exist
	 * @return property map
	 * @throws PropertyTypeMismatchException if a conflicting map definition was found
	 */
	public VoidPropertyMap getBooleanProperty(String owner, String propertyName, boolean create)
			throws PropertyTypeMismatchException;

	/**
	 * Get a address-based Saveable-object property map
	 * @param owner name of property owner (e.g., plugin name)
	 * @param propertyName
	 * @param create creates the property map if it does not exist
	 * @return property map
	 * @throws PropertyTypeMismatchException if a conflicting map definition was found
	 */
	public ObjectPropertyMap getObjectProperty(String owner, String propertyName,
			Class<? extends Saveable> saveableObjectClass, boolean create);

	/**
	 * Get all property maps associated with a specific owner.
	 * @param owner name of property owner (e.g., plugin name)
	 * @return list of property maps
	 */
	public List<PropertyMap> getProperties(String owner);

	/**
	 * Returns list of all property owners for which property maps have been defined.
	 */
	public List<String> getPropertyOwners();

	/**
	 * Returns all properties lists contained by this domain object.
	 * 
	 * @return all property lists contained by this domain object.
	 */
	public List<String> getOptionsNames();

	/**
	 * Get the property list for the given name.
	 * @param propertyListName name of property list
	 */
	public Options getOptions(String propertyListName);
}

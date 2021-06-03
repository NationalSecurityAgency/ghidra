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
package ghidra.program.model.symbol;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Library;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * External manager interface. Defines methods for dealing with external programs and locations
 * within those programs.
 */

public interface ExternalManager {

	/**
	 * Returns a list of all external names for which locations have been defined.
	 */
	public String[] getExternalLibraryNames();

	/**
	 * Get the Library which corresponds to the specified name
	 * @param name name of library
	 * @return library or null if not found
	 */
	public Library getExternalLibrary(String name);

	/**
	 * Removes external name if no associated ExternalLocation's exist
	 * @param name external name
	 * @return true if removed, false if unable to due to associated locations/references
	 */
	public boolean removeExternalLibrary(String name);

	/**
	 * Returns the file pathname associated with an external name.
	 * Null is returned if either the external name does not exist or
	 * a pathname has not been set.
	 * @param libraryName external name
	 */
	public String getExternalLibraryPath(String libraryName);

	/**
	 * Sets the file pathname associated with an existing external name.
	 * @param libraryName the name of the library to associate with a file.
	 * @param pathname the path to the program to be associated with the library name.
	 * @param userDefined true if the external path is being specified by the user
	 */
	public void setExternalPath(String libraryName, String pathname, boolean userDefined)
			throws InvalidInputException;

	/**
	 * Change the name of an existing external name.
	 * @param oldName the old name of the external library name.
	 * @param newName the new name of the external library name.
	 * @param source the source of this external library
	 */
	public void updateExternalLibraryName(String oldName, String newName, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Get an iterator over all external locations associated with the specified
	 * externalName.
	 * @param libraryName the name of the library to get locations for
	 * @return external location iterator
	 */
	public ExternalLocationIterator getExternalLocations(String libraryName);

	/**
	 * Get an iterator over all external locations which have been associated to
	 * the specified memory address
	 * @param memoryAddress
	 * @return external location iterator
	 */
	public ExternalLocationIterator getExternalLocations(Address memoryAddress);

	/**
	 * Get an external location.
	 * @param libraryName the name of the library for which to get an external location
	 * @param label the name of the external location.
	 * @deprecated Use  {@link #getExternalLocations(String, String)} instead
	 */
	@Deprecated
	public ExternalLocation getExternalLocation(String libraryName, String label);

	/**
	 * Get an external location.
	 * @param namespace the namespace containing the external label.
	 * @param label the name of the external location.
	 * @deprecated Use {@link #getExternalLocations(Namespace, String)}
	 */
	@Deprecated
	public ExternalLocation getExternalLocation(Namespace namespace, String label);

	/**
	 * Returns a list of External Locations matching the given label name in the given Library.
	 * @param libraryName the name of the library
	 * @param label the name of the label
	 * @return a list of External Locations matching the given label name in the given Library.
	 */
	public List<ExternalLocation> getExternalLocations(String libraryName, String label);

	/**
	 * Returns a list of External Locations matching the given label name in the given Namespace.
	 * @param namespace the Namespace to search
	 * @param label the name of the labels to search for.
	 * @return a list of External Locations matching the given label name in the given Namespace.
	 */
	public List<ExternalLocation> getExternalLocations(Namespace namespace, String label);

	/**
	 * Returns the unique external location associated with the given library name and label
	 * @param libraryName the library name
	 * @param label the label of the external location
	 * @return the unique external location or null
	 */
	public ExternalLocation getUniqueExternalLocation(String libraryName, String label);

	/**
	 * Returns the unique external location associated with the given namespace and label
	 * @param namespace the namespace
	 * @param label the label of the external location
	 * @return the unique external location or null
	 */
	public ExternalLocation getUniqueExternalLocation(Namespace namespace, String label);

	/**
	 * Returns the external location associated with the given external symbol
	 * @param symbol the external symbol.
	 * @return the external location or null
	 */
	public ExternalLocation getExternalLocation(Symbol symbol);

	/**
	 * Determines if the indicated external library name is being managed (exists).
	 * @param libraryName the external library name
	 * @return true if the name is defined (whether it has a path or not).
	 */
	public boolean contains(String libraryName);

	/**
	 * Adds a new external library name
	 * @param name the new library name to add.
	 * @param source the source of this external library
	 * @return library
	 */
	public Library addExternalLibraryName(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Get or create an external location associated with an library/file named extName
	 * and the label within that file specified by extLabel
	 * @param extName the external name
	 * @param extLabel the external label
	 * @param extAddr the external address
	 * @param sourceType the source type of this external library's symbol
	 * @return external location
	 * @throws InvalidInputException
	 * @throws DuplicateNameException
	 */
	public ExternalLocation addExtLocation(String extName, String extLabel, Address extAddr,
			SourceType sourceType) throws InvalidInputException, DuplicateNameException;

	/**
	 * Get or create an external location in the indicated parent namespace with the specified name.
	 * @param extNamespace the external namespace
	 * @param extLabel the external label
	 * @param extAddr the external address
	 * @param sourceType the source type of this external library's symbol
	 * @return external location
	 * @throws InvalidInputException
	 * @throws DuplicateNameException
	 */
	public ExternalLocation addExtLocation(Namespace extNamespace, String extLabel, Address extAddr,
			SourceType sourceType) throws InvalidInputException, DuplicateNameException;

	/**
	 * Get or create an external location in the indicated parent namespace with the specified name.
	 * @param extNamespace the external namespace
	 * @param extLabel the external label
	 * @param extAddr the external address
	 * @param sourceType the source type of this external library's symbol
	 * @param reuseExisting if true, this will return an existing matching external
	 * location instead of creating a new one.
	 * @return external location
	 * @throws InvalidInputException
	 * @throws DuplicateNameException
	 */
	public ExternalLocation addExtLocation(Namespace extNamespace, String extLabel, Address extAddr,
			SourceType sourceType, boolean reuseExisting)
			throws InvalidInputException, DuplicateNameException;

	/**
	 * Get or create an external location associated with an library/file named extName
	 * and the label within that file specified by extLabel
	 * @param extName the external name
	 * @param extLabel the external label
	 * @param extAddr the external address
	 * @param sourceType the source type of this external library's symbol
	 * @return external location
	 * @throws InvalidInputException
	 * @throws DuplicateNameException
	 */
	public ExternalLocation addExtFunction(String extName, String extLabel, Address extAddr,
			SourceType sourceType) throws DuplicateNameException, InvalidInputException;

	/**
	 * Get or create an external function location associated with an library/file named extName
	 * and the label within that file specified by extLabel
	 * @param extNamespace the external namespace
	 * @param extLabel the external label
	 * @param extAddr the external address
	 * @param sourceType the source type of this external library's symbol
	 * @return external location
	 * @throws InvalidInputException
	 * @throws DuplicateNameException if another non-Library namespace has the same name
	 */
	public ExternalLocation addExtFunction(Namespace extNamespace, String extLabel, Address extAddr,
			SourceType sourceType) throws InvalidInputException, DuplicateNameException;

	/**
	 * Get or create an external function location associated with an library/file named extName
	 * and the label within that file specified by extLabel
	 * @param extNamespace the external namespace
	 * @param extLabel the external label
	 * @param sourceType the source type of this external library's symbol
	 * @param reuseExisting if true, will return any existing matching location instead of
	 * creating a new one. If false, will prefer to create a new one as long as the specified
	 * address is not null and not used in an existing location.
	 * @return external location
	 * @throws InvalidInputException
	 * @throws DuplicateNameException if another non-Library namespace has the same name
	 */
	public ExternalLocation addExtFunction(Namespace extNamespace, String extLabel, Address extAddr,
			SourceType sourceType, boolean reuseExisting)
			throws InvalidInputException, DuplicateNameException;

}

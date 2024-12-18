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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * External manager interface. Defines methods for dealing with external programs and locations
 * within those programs.
 */

public interface ExternalManager {

	/**
	 * Returns an array of all external names for which locations have been defined.
	 * @return array of external names
	 */
	public String[] getExternalLibraryNames();

	/**
	 * Get the Library which corresponds to the specified name
	 * @param libraryName name of library
	 * @return library or null if not found
	 */
	public Library getExternalLibrary(String libraryName);

	/**
	 * Removes external name if no associated ExternalLocation's exist
	 * @param libraryName external library name
	 * @return true if removed, false if unable to due to associated locations/references
	 */
	public boolean removeExternalLibrary(String libraryName);

	/**
	 * Returns the file pathname associated with an external name.
	 * Null is returned if either the external name does not exist or
	 * a pathname has not been set.
	 * @param libraryName external name
	 * @return project file pathname or null
	 */
	public String getExternalLibraryPath(String libraryName);

	/**
	 * Sets the file pathname associated with an existing external name.
	 * @param libraryName the name of the library to associate with a file.
	 * @param pathname the path to the program to be associated with the library name.
	 * @param userDefined true if the external path is being specified by the user
	 * @throws InvalidInputException on invalid input
	 */
	public void setExternalPath(String libraryName, String pathname, boolean userDefined)
			throws InvalidInputException;

	/**
	 * Change the name of an existing external name.
	 * @param oldName the old name of the external library name.
	 * @param newName the new name of the external library name.
	 * @param source the source of this external library
	 * @throws DuplicateNameException if another namespace has the same name
	 * @throws InvalidInputException on invalid input
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
	 * @param memoryAddress memory address
	 * @return external location iterator
	 */
	public ExternalLocationIterator getExternalLocations(Address memoryAddress);

	/**
	 * Get an external location.
	 * @param libraryName the name of the library for which to get an external location
	 * @param label the name of the external location.
	 * @return first matching external location
	 * @deprecated Use  {@link #getExternalLocations(String, String)} or 
	 * {@link #getUniqueExternalLocation(String, String)} since duplicate names may exist
	 */
	@Deprecated
	public ExternalLocation getExternalLocation(String libraryName, String label);

	/**
	 * Get an external location.
	 * @param namespace the namespace containing the external label.
	 * @param label the name of the external location.
	 * @return first matching external location
	 * @deprecated Use {@link #getExternalLocations(Namespace, String)} or 
	 * {@link #getUniqueExternalLocation(Namespace, String)} since duplicate names may exist
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
	 * @param libraryName the new external library name to add.
	 * @param source the source of this external library
	 * @return library external {@link Library namespace}
	 * @throws InvalidInputException if {@code libraryName} is invalid or null.  A library name 
	 * with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws DuplicateNameException if another non-Library namespace has the same name
	 */
	public Library addExternalLibraryName(String libraryName, SourceType source)
			throws InvalidInputException, DuplicateNameException;

	/**
	 * Get or create an external location associated with a library/file named {@code libraryName}
	 * and the location within that file identified by {@code extLabel} and/or its memory address
	 * {@code extAddr}.  Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * @param libraryName the external library name
	 * @param extLabel the external label or null
	 * @param extAddr the external memory address or null
	 * @param sourceType the source type of this external library's symbol
	 * @return external location
	 * @throws InvalidInputException if {@code libraryName} is invalid or null, or an invalid 
	 * {@code extlabel} is specified.  Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws DuplicateNameException if another non-Library namespace has the same name
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public ExternalLocation addExtLocation(String libraryName, String extLabel, Address extAddr,
			SourceType sourceType) throws InvalidInputException, DuplicateNameException;

	/**
	 * Create an external location in the indicated external parent namespace 
	 * and identified by {@code extLabel} and/or its memory address
	 * {@code extAddr}.  Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * @param extNamespace the external namespace
	 * @param extLabel the external label or null
	 * @param extAddr the external memory address or null
	 * @param sourceType the source type of this external library's symbol
	 * @return external location
	 * @throws InvalidInputException if an invalid {@code extlabel} is specified.  
	 * Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public ExternalLocation addExtLocation(Namespace extNamespace, String extLabel, Address extAddr,
			SourceType sourceType) throws InvalidInputException;

	/**
	 * Get or create an external location in the indicated external parent namespace 
	 * and identified by {@code extLabel} and/or its memory address
	 * {@code extAddr}.  Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * @param extNamespace the external namespace
	 * @param extLabel the external label or null
	 * @param extAddr the external memory address or null
	 * @param sourceType the source type of this external library's symbol
	 * @param reuseExisting if true, this will return an existing matching external
	 * location instead of creating a new one.
	 * @return external location
	 * @throws InvalidInputException if an invalid {@code extlabel} is specified.  
	 * Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public ExternalLocation addExtLocation(Namespace extNamespace, String extLabel, Address extAddr,
			SourceType sourceType, boolean reuseExisting)
			throws InvalidInputException;

	/**
	 * Create an external {@link Function} in the external {@link Library} namespace 
	 * {@code libararyName} and identified by {@code extLabel} and/or its memory address
	 * {@code extAddr}.  Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * @param libraryName the external library name
	 * @param extLabel label within the external program, may be null if extAddr is not null
	 * @param extAddr memory address within the external program, may be null
	 * @param sourceType the source type of this external library's symbol
	 * @return external location
	 * @throws InvalidInputException if {@code libraryName} is invalid or null, or an invalid 
	 * {@code extlabel} is specified.  Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws DuplicateNameException if another non-Library namespace has the same name
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public ExternalLocation addExtFunction(String libraryName, String extLabel, Address extAddr,
			SourceType sourceType) throws InvalidInputException, DuplicateNameException;

	/**
	 * Create an external {@link Function} in the indicated external parent namespace 
	 * and identified by {@code extLabel} and/or its memory address
	 * {@code extAddr}.  Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * @param extNamespace the external namespace
	 * @param extLabel the external label or null
	 * @param extAddr the external memory address or null
	 * @param sourceType the source type of this external library's symbol
	 * @return external location
	 * @throws InvalidInputException if an invalid {@code extlabel} is specified.  
	 * Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public ExternalLocation addExtFunction(Namespace extNamespace, String extLabel, Address extAddr,
			SourceType sourceType) throws InvalidInputException;

	/**
	 * Get or create an external {@link Function} in the indicated external parent namespace 
	 * and identified by {@code extLabel} and/or its memory address
	 * {@code extAddr}.  Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * @param extNamespace the external namespace
	 * @param extLabel the external label or null
	 * @param extAddr the external memory address or null
	 * @param sourceType the source type of this external library's symbol
	 * @param reuseExisting if true, will return any existing matching location instead of
	 * creating a new one. If false, will prefer to create a new one as long as the specified
	 * address is not null and not used in an existing location.
	 * @return external location
	 * @throws InvalidInputException if an invalid {@code extlabel} is specified.  
	 * Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public ExternalLocation addExtFunction(Namespace extNamespace, String extLabel, Address extAddr,
			SourceType sourceType, boolean reuseExisting)
			throws InvalidInputException;

}

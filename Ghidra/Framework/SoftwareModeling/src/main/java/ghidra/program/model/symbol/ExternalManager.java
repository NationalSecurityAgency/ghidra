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
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * External manager interface. Defines methods for dealing with external libraries/programs 
 * and associated {@link ExternalLocation} symbols used to reference locations within them.
 * When a specific library is unknown, an external location may be associated with the
 * {@link Library#UNKNOWN} library until a more suitable named library can be identified.
 * <p>
 * An {@link ExternalLocation} may be a {@link Function} or a generic location.  
 * <p>
 * When creating a location with a mangled name it must be created within the global namespace 
 * to ensure that it will be considered for demangling.  Once demangled, the original mangled
 * name gets saved to the location object's 
 * {@link ExternalLocation#getOriginalImportedName() original imported name}.  
 */
public interface ExternalManager {

	/**
	 * Returns an array of all external Library names sorted by preferred search order.
	 * This order reflects the preferred search order when looking for external symbols
	 * which were not linked to a specific Library.
	 * <p>
	 * NOTE: The {@link Library#UNKNOWN} library will always be returned as first in the list
	 * but will not have an associated program path and cannot be searched.
	 * 
	 * @return array of all external Library names sorted by preferred search order.
	 */
	public String[] getExternalLibraryNames();

	/**
	 * Get a list of all external Libraries sorted by preferred search order. 
	 * This order reflects the preferred search order when looking for external symbols
	 * which were not linked to a specific Library.
	 * <p>
	 * NOTE: The {@link Library#UNKNOWN} library will always be returned as first in the list
	 * but will not have an associated program path and cannot be searched.
	 * 
	 * @return list of all external Libraries sorted by preferred search order.
	 */
	public List<Library> getLibraries();

	/**
	 * Get the Library which corresponds to the specified name
	 * 
	 * @param libraryName name of library
	 * @return library or null if not found
	 */
	public Library getExternalLibrary(String libraryName);

	/**
	 * Removes external name if no associated ExternalLocation's exist
	 * 
	 * @param libraryName external library name
	 * @return true if removed, false if unable to due to associated locations/references
	 */
	public boolean removeExternalLibrary(String libraryName);

	/**
	 * Returns the file pathname associated with an external name.
	 * Null is returned if either the external name does not exist or
	 * a pathname has not been set.
	 * 
	 * @param libraryName external name
	 * @return project file pathname or null
	 */
	public String getExternalLibraryPath(String libraryName);

	/**
	 * Sets the file pathname associated with an external name.
	 * If the Library namespace/symbol does not already exist it will be created provided
	 * the libraryName does not conflict with another namespace whose parent is the global
	 * namespace.
	 * <p>
	 * NOTE: Assigning path for {@link Library#UNKNOWN} Library will be ignored.
	 * <p>
	 * NOTE: Assigning path to a non-Library namespace will fail silently.
	 *
	 * @param libraryName the name of the library to associate with a file.
	 * @param pathname the path to the program to be associated with the library name.
	 * @param userDefined true if the external path is being specified by the user
	 * @throws InvalidInputException on invalid input specified
	 */
	public void setExternalPath(String libraryName, String pathname, boolean userDefined)
			throws InvalidInputException;

	/**
	 * {@return the ordinal associated with an external library which represents its 
	 * sequence within the order list of libraries or -1 if library name not found}
	 * 
	 * @param libraryName the library name
	 */
	public int getLibraryOrdinal(String libraryName);

	/**
	 * Sets the Library search ordinal associated with an external name.
	 * <p>
	 * Assigning ordinal for {@link Library#UNKNOWN} Library will fail and return -1.
	 * Assigning ordinal to a non-existing Library will fail and return -1.
	 * <p>
	 * NOTE: The actual ordinal applied my be limited based on placement restrictions.
	 * 
	 * @param libraryName the name of the library to position within Library search sequence
	 * @param ordinal library ordinal greater or equal to 1
	 * @return the actual ordinal applied or -1 if change failed.
	 */
	public int setLibraryOrdinal(String libraryName, int ordinal);

	/**
	 * Change the name of an existing external name.
	 * 
	 * @param oldName the old name of the external library name.
	 * @param newName the new name of the external library name.
	 * @param source the source of this external library
	 * @return true if symbol was found and renamed, false if symbol not found
	 * @throws DuplicateNameException if name conflicts with another symbol.
	 * @throws InvalidInputException if an invalid or null name specified (see 
	 * {@link SymbolUtilities#validateName}).
	 */
	public boolean updateExternalLibraryName(String oldName, String newName, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Get an iterator over all external locations associated with the specified Library.
	 * 
	 * @param libraryName the name of the library to get locations for
	 * @return external location iterator
	 */
	public ExternalLocationIterator getExternalLocations(String libraryName);

	/**
	 * Get an iterator over all external locations which have been associated to
	 * the specified memory address
	 * 
	 * @param memoryAddress memory address
	 * @return external location iterator
	 */
	public ExternalLocationIterator getExternalLocations(Address memoryAddress);

	/**
	 * Returns a set of External Locations matching the given label name in the specified Library.
	 * If searching for an original import name, which should not be constrained to a specific 
	 * library (e.g., mangled name), null should be specified for the libraryName.
	 * <p>
	 * NOTE: Only those external symbols which are contained within the global namespace will be 
	 * included.
	 * 
	 * @param libraryName the name of the library (may be null to consider all libraries)
	 * @param label the name of the label
	 * @return a list of External Locations matching the given label name in the given Library.
	 */
	public Set<ExternalLocation> getExternalLocations(String libraryName, String label);

	/**
	 * Returns a set of External Locations matching the given label within an optional namespace and library.
	 * If searching for an original import name which should not be constrained to a specific 
	 * library (e.g., mangled name), null should be specified for both library and namespace.  If a namespace 
	 * is specified the original import name will not be searched.
	 * 
	 * @param library the external library (may be null to consider all libraries)
	 * @param namespace the namespace within which the label should be searched for (may be null for global namespace)
	 * @param label the name of the labels to search for.
	 * @return a list of External Locations matching the given label name in the given Namespace.
	 */
	public Set<ExternalLocation> getExternalLocations(Library library, Namespace namespace,
			String label);

	/**
	 * Returns the unique external location associated with the given library name and label.
	 * If searching for an original import name, which should not be constrained to a specific 
	 * library (e.g., mangled name), null should be specified for the libraryName.
	 * <p>
	 * NOTE: Only those external symbols which are contained within the global namespace will be 
	 * included.
	 * 
	 * @param libraryName the library name or null
	 * @param label the label of the external location
	 * @return the unique external location or null
	 */
	public ExternalLocation getUniqueExternalLocation(String libraryName, String label);

	/**
	 * Returns the unique external location associated with the given library, namespace and label.
	 * If searching for an original import name which should not be constrained to a specific 
	 * library (e.g., mangled name), null may be specified for the library.  If a namespace 
	 * is specified the original import name will not be searched.
	 * 
	 * @param library the library or null
	 * @param namespace the namespace within which the label should be searched for (may be null for global namespace)
	 * @param label the label of the external location
	 * @return the unique external location or null
	 */
	public ExternalLocation getUniqueExternalLocation(Library library, Namespace namespace,
			String label);

	/**
	 * Returns the external location associated with the given external symbol
	 * @param symbol the external symbol.
	 * @return the external location or null
	 */
	public ExternalLocation getExternalLocation(Symbol symbol);

	/**
	 * Determines if the indicated external library name is being managed (exists).
	 * 
	 * @param libraryName the external library name
	 * @return true if the name is defined (whether it has a path or not).
	 */
	public boolean contains(String libraryName);

	/**
	 * Adds a new external library name
	 * 
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
	 * Get or create an external location associated with a specified library
	 * and identified by {@code extLabel} and/or its memory address {@code extAddr}.  
	 * Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * <p>
	 * NOTE: The result location will be created within the global namespace.
	 * 
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
	 * Get or create an external location associated with a specified library
	 * and identified by {@code extLabel} and/or its memory address {@code extAddr}.  
	 * Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * <p>
	 * NOTE: The result location will be created within the global namespace.
	 * 
	 * @param library The external library
	 * @param extLabel the external label or null
	 * @param extAddr the external memory address or null
	 * @param sourceType the source type of this external library's symbol
	 * @return external location
	 * @throws InvalidInputException if an invalid {@code extlabel} is specified.  
	 * Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public default ExternalLocation addExtLocation(Library library, String extLabel,
			Address extAddr, SourceType sourceType) throws InvalidInputException {
		return addExtLocation(library, null, extLabel, extAddr, sourceType, true);
	}

	/**
	 * Get or create an external location associated with a specified library and namespace,
	 * and identified by {@code extLabel} and/or its memory address {@code extAddr}.  
	 * Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * <p>
	 * NOTE: If the extLabel is null the global or null namespace should be specified.
	 * 
	 * @param library The external library
	 * @param namespace the namespace or null for the global namespace
	 * @param extLabel the external label or null
	 * @param extAddr the external memory address or null
	 * @param sourceType the source type of this external library's symbol
	 * @return external location
	 * @throws InvalidInputException if an invalid {@code extlabel} is specified.  
	 * Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public default ExternalLocation addExtLocation(Library library, Namespace namespace,
			String extLabel, Address extAddr, SourceType sourceType) throws InvalidInputException {
		return addExtLocation(library, namespace, extLabel, extAddr, sourceType, true);
	}

	/**
	 * Get or create an external location associated with a specified library and namespace,
	 * and identified by {@code extLabel} and/or its memory address {@code extAddr}.  
	 * Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * <p>
	 * NOTE: The result location will be created within the global namespace.
	 * 
	 * @param library the external library
	 * @param extLabel the external label or null
	 * @param extAddr the external memory address or null
	 * @param sourceType the source type of this external library's symbol
	 * @param reuseExisting if true, will return any existing matching location instead of
	 * creating a new one if a suitable match is found. If false, the method will create a 
	 * new one as long as an extLabel has been specified.
	 * @return external location
	 * @throws InvalidInputException if an invalid {@code extlabel} is specified.  
	 * Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public default ExternalLocation addExtLocation(Library library, String extLabel,
			Address extAddr, SourceType sourceType, boolean reuseExisting)
			throws InvalidInputException {
		return addExtLocation(library, null, extLabel, extAddr, sourceType, reuseExisting);
	}

	/**
	 * Get or create an external location associated with a specified library and namespace,
	 * and identified by {@code extLabel} and/or its memory address {@code extAddr}.  
	 * Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * <p>
	 * NOTE: If the extLabel is null the global or null namespace should be specified.
	 * 
	 * @param library the external library
	 * @param namespace the namespace or null for the global namespace
	 * @param extLabel the external label or null
	 * @param extAddr the external memory address or null
	 * @param sourceType the source type of this external library's symbol
	 * @param reuseExisting if true, will return any existing matching location instead of
	 * creating a new one if a suitable match is found. If false, the method will create a 
	 * new one as long as an extLabel has been specified.
	 * @return external location
	 * @throws InvalidInputException if an invalid {@code extlabel} is specified.  
	 * Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public ExternalLocation addExtLocation(Library library, Namespace namespace, String extLabel,
			Address extAddr, SourceType sourceType, boolean reuseExisting)
			throws InvalidInputException;

	/**
	 * Get or create an external {@link Function} location associated with a specified library
	 * and identified by {@code extLabel} and/or its memory address {@code extAddr}.  
	 * Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * <p>
	 * NOTE: The result location will be created within the global namespace.
	 * 
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
	 * Get or create an external {@link Function} location associated with a specified library
	 * and identified by {@code extLabel} and/or its memory address {@code extAddr}.  
	 * Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * <p>
	 * NOTE: The result location will be created within the global namespace.
	 * 
	 * @param library the external library
	 * @param extLabel the external label or null
	 * @param extAddr the external memory address or null
	 * @param sourceType the source type of this external library's symbol
	 * @return external location
	 * @throws InvalidInputException if an invalid {@code extlabel} is specified.  
	 * Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public default ExternalLocation addExtFunction(Library library, String extLabel,
			Address extAddr, SourceType sourceType) throws InvalidInputException {
		return addExtFunction(library, null, extLabel, extAddr, sourceType, true);
	}

	/**
	 * Get or create an external {@link Function} location associated with a specified library
	 * and identified by {@code extLabel} and/or its memory address {@code extAddr}.  
	 * Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * <p>
	 * NOTE: The result location will be created within the global namespace.
	 * 
	 * @param library the external library
	 * @param extLabel the external label or null
	 * @param extAddr the external memory address or null
	 * @param sourceType the source type of this external library's symbol
	 * @param reuseExisting if true, will return any existing matching location instead of
	 * creating a new one if a suitable match is found. If false, the method will create a 
	 * new one as long as an extLabel has been specified.
	 * @return external location
	 * @throws InvalidInputException if an invalid {@code extlabel} is specified.  
	 * Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public default ExternalLocation addExtFunction(Library library, String extLabel,
			Address extAddr, SourceType sourceType, boolean reuseExisting)
			throws InvalidInputException {
		return addExtFunction(library, null, extLabel, extAddr, sourceType, reuseExisting);
	}

	/**
	 * Get or create an external {@link Function} location associated with a specified library and namespace,
	 * and identified by {@code extLabel} and/or its memory address {@code extAddr}.  
	 * Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * <p>
	 * NOTE: If the extLabel is null the global or null namespace should be specified.
	 * 
	 * @param library the external library
	 * @param namespace the namespace or null for the global namespace
	 * @param extLabel the external label or null
	 * @param extAddr the external memory address or null
	 * @param sourceType the source type of this external library's symbol
	 * @return external location
	 * @throws InvalidInputException if an invalid {@code extlabel} is specified.  
	 * Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public default ExternalLocation addExtFunction(Library library, Namespace namespace,
			String extLabel, Address extAddr, SourceType sourceType) throws InvalidInputException {
		return addExtFunction(library, namespace, extLabel, extAddr, sourceType, true);
	}

	/**
	 * Get or create an external {@link Function} location associated with a specified library and namespace,
	 * and identified by {@code extLabel} and/or its memory address
	 * {@code extAddr}.  Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * <p>
	 * NOTE: If the extLabel is null the global or null namespace should be specified.
	 * 
	 * @param library the external library
	 * @param namespace the namespace or null for the global namespace
	 * @param extLabel the external label or null
	 * @param extAddr the external memory address or null
	 * @param sourceType the source type of this external library's symbol
	 * @param reuseExisting if true, will return any existing matching location instead of
	 * creating a new one if a suitable match is found. If false, the method will create a 
	 * new one as long as an extLabel has been specified.
	 * @return external location
	 * @throws InvalidInputException if an invalid {@code extlabel} is specified.  
	 * Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public ExternalLocation addExtFunction(Library library, Namespace namespace, String extLabel,
			Address extAddr, SourceType sourceType, boolean reuseExisting)
			throws InvalidInputException;

}

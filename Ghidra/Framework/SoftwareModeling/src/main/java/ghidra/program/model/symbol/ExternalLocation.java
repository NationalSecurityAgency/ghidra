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

import ghidra.app.util.SymbolPath;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * <code>ExternalLocation</code> defines a location within an external
 * program (i.e., library).  The external program is uniquely identified
 * by a program name, and the location within the program is identified by
 * label, address or both.
 */
public interface ExternalLocation {

	/**
	 * Returns the symbol associated with this external location or null.
	 * @return the symbol associated with this external location or null.
	 */
	public Symbol getSymbol();

	/**
	 * Returns the name of the external program containing this location.
	 * @return  the name of the external program containing this location.
	 */
	public String getLibraryName();

	/**
	 * Returns the parent namespace containing this location.
	 * @return the parent namespace containing this location.
	 */
	public Namespace getParentNameSpace();

	/**
	 * Returns the name of the parent namespace containing this location.
	 * @return  the name of the parent namespace containing this location.
	 */
	public String getParentName();

	/**
	 * Returns the external label associated with this location.
	 * @return  the external label associated with this location.
	 */
	public String getLabel();

	/**
	 * Returns the original name for this location. Will be null if the name was never
	 * changed.
	 * @return the original name for this location. Will be null if the name was never
	 * changed.
	 */
	public String getOriginalImportedName();

	/**
	 * Returns the source of this location.
	 * @return the source
	 */
	public SourceType getSource();

	/**
	 * Returns the external address if known, or null
	 * @return the external address if known, or null
	 */
	public Address getAddress();

	/**
	 * Sets the address in the external program associated with this location.
	 * The address may not be null if location has a default label.
	 * @param address the address to set.
	 * @throws InvalidInputException if address is null and location currently has a default name
	 */
	public void setAddress(Address address) throws InvalidInputException;

	/**
	 * Set the external label which defines this location.
	 * @param label external label, may be null if addr is not null.  Label may also be
	 * namespace qualified and best effort will be used to parse namespace (see {@link SymbolPath}).
	 * If a namespace is not included within label, the current namespace will be preserved.
	 * Note that this method does not properly handle the presence of template information within the
	 * label.
	 * @param addr external address, may be null
	 * @param source the source of the external label name
	 * @throws DuplicateNameException if another location with this label has
	 * already been defined
	 * @throws InvalidInputException
	 */
	public void setLocation(String label, Address addr, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * @return true if location corresponds to a function
	 */
	public boolean isFunction();

	/**
	 * Returns the DataType which has been associated with this location.
	 */
	public DataType getDataType();

	/**
	 * Associate the specified data type with this location.
	 * @param dt data type
	 */
	public void setDataType(DataType dt);

	/**
	 * Returns the external function associated with this location or null if this is a data
	 * location.
	 * @return external function associated with this location or null
	 * if this is a data location.
	 */
	public Function getFunction();

	/**
	 * Create an external function associated with this location or return
	 * the existing function if one already exists
	 * @return external function
	 */
	public Function createFunction();

	/**
	 * Returns the address in "External" (fake) space where this location is stored.
	 * @return the address that represents this location in "External" space.
	 */
	public Address getExternalSpaceAddress();

	/**
	 * Set a new name for this external location. The new
	 * name will become the primary symbol for this location. The current name
	 * for this location will be saved as the original symbol for this location.
	 * @param namespace the namespace for the original symbol.  Can be different than original symbol
	 * @param name the user-friendly name.
	 * @param sourceType the SourceType for the new name.
	 * @throws InvalidInputException if the name contains illegal characters (space for example)
	 */
	public void setName(Namespace namespace, String name, SourceType sourceType)
			throws InvalidInputException;

	/**
	 * If this external location has a replacement name, then the primary symbol will be deleted and
	 * the original symbol will become the primary symbol, effectively restoring the location to
	 * it's original name.
	 */
	public void restoreOriginalName();

	/**
	 * Returns true if the given external location has the same name, namespace, original import name,
	 * and external address.
	 * @param other the other ExternalLocation to compare
	 * @return true if the other location is equivalent to this one.
	 */
	public boolean isEquivalent(ExternalLocation other);

}

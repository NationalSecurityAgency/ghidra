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

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * The Namespace interface
 */
public interface Namespace {
	static final long GLOBAL_NAMESPACE_ID = 0;
	/**
	 * The delimiter that is used to separate namespace nodes in a namespace
	 * string.  For example, "Global::child1::symbolName"
	 */
	public static final String DELIMITER = "::";

	/**
	 * Replaced by {@link #DELIMITER}
	 * @deprecated use {@link #DELIMITER}
	 */
	@Deprecated
	public static final String NAMESPACE_DELIMITER = "::";

	/**
	 * Get the symbol for this namespace; Note: The global namespace will return null
	 * @return the symbol for this namespace; Note: The global namespace will return null
	 */
	public Symbol getSymbol();

	/**
	 * Returns true if this namespace is external (i.e., associated with a Library)
	 * @return true if this namespace is external (i.e., associated with a Library)
	 */
	public boolean isExternal();

	/**
	 * Get the name of the symbol for this scope
	 * @return the name of the symbol for this scope
	 */
	public String getName();

	/**
	 * Returns the fully qualified name
	 * @param includeNamespacePath true to include the namespace in the returned name
	 * @return the fully qualified name
	 */
	public String getName(boolean includeNamespacePath);

	/**
	 * Return the namespace id
	 * @return the namespace id
	 */
	public long getID();

	/**
	 * Get the parent scope.
	 * @return null if this scope is the global scope.
	 */
	public Namespace getParentNamespace();

	/**
	 * Get the address set for this namespace.  Note: The body of a namespace (currently
	 * only used by the function namespace) is restricted it Integer.MAX_VALUE.
	 * @return the address set for this namespace
	 */
	public AddressSetView getBody();

	/**
	 * Set the parent namespace for this namespace. Restrictions may apply.
	 * @param parentNamespace the namespace to use as this namespace's parent.
	 * @throws InvalidInputException if the parent namespace is not applicable for
	 * this namespace.
	 * @throws DuplicateNameException if another symbol exists in the parent namespace with
	 * the same name as this namespace
	 * @throws CircularDependencyException if the parent namespace is a descendent of this
	 * namespace.
	 */
	public void setParentNamespace(Namespace parentNamespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException;

	/**
	 * Return true if this is the global namespace;
	 * @return  true if this is the global namespace;
	 */
	public default boolean isGlobal() {
		return getID() == GLOBAL_NAMESPACE_ID;
	}

}

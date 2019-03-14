/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.program.model.address.Address;

/**
 * Listener methods that are called when changes to symbols are made.
 */
public interface SymbolTableListener {

	/**
	 * Notification that the given symbol has been added.
	 * @param symbol the symbol that was added.
	 */
	public void symbolAdded(SourceType symbol);
	
	/**
	 * Notification that a symbol was removed.
	 * @param addr address where the symbol was
	 * @param name name of symbol
	 * @param isLocal true if the symbol was in the scope
	 * of a function
	 */
	public void symbolRemoved(Address addr, String name, boolean isLocal);

	/**
	 * Notification that the given symbol was renamed.
	 * @param symbol symbol that was renamed
	 * @param oldName old name of the symbol
	 */
	public void symbolRenamed(SourceType symbol, String oldName);

	/**
	 * Notification the the given symbol was set as the primary symbol.
	 * @param symbol the symbol that is now primary.
	 */
	public void primarySymbolSet(SourceType symbol);

	/**
	 * Notification that the scope on a symbol changed.
	 * @param symbol the symbol whose scope has changed.
	 */
	public void symbolScopeChanged(SourceType symbol);

	/**
	 * Notification that an external entry point was added at the
	 * given address.
	 * @param addr the address that made an external entry point.
	 */
	public void externalEntryPointAdded(Address addr);

	/**
	 * Notification that an external entry point was removed from the given
	 * address.
	 * @param addr the address the removed as an external entry point.
	 */
	public void externalEntryPointRemoved(Address addr);

	/**
	 * Notification that the association between a reference and a 
	 * specific symbol has changed.
	 * @param symbol affected symbol
	 * @param ref affected reference
	 */
	public void associationAdded(SourceType symbol, Reference ref);

	/**
	 * Notification that the association between the given reference and
	 * any symbol was removed.
	 * @param ref the reference that had a symbol association removed.
	 */
	public void associationRemoved(Reference ref);
}

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
package ghidra.program.model.listing;

import ghidra.framework.model.ChangeSet;

/**
 * Interface for a Symbol Change set.  Objects that implements this interface track
 * various change information on a symbol manager.
 */
public interface SymbolChangeSet extends ChangeSet {

	//
	// Symbols
	//
	
	/**
	 * adds the symbol id to the list of symbols that have changed.
	 */
	void symbolChanged(long id);
	
	/**
	 * adds the symbols id to the list of symbols that have been added.
	 */
	void symbolAdded(long id);
	
	/**
	 * returns the list of symbol IDs that have changed.
	 */
	long[] getSymbolChanges();
	
	/**
	 * returns the list of symbols IDs that have been added.
	 */
	long[] getSymbolAdditions();

}

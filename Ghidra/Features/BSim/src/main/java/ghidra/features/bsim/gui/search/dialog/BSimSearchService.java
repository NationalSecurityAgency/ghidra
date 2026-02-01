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
package ghidra.features.bsim.gui.search.dialog;

import java.util.Set;

import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.program.database.symbol.FunctionSymbol;

/**
 * Interface used by the BSimSearchDialog to initiate BSim Queries
 */
public interface BSimSearchService {

	/**
	 * Returns the BSimServerInfo that was used in the previous search or null if no searches
	 * have been performed.
	 * @return the BSimServerInfo that was used in the previous search 
	 */
	public BSimServerInfo getLastUsedServer();

	/**
	 * Returns the BSimSearchSettings that was used in the previous search or the default
	 * settings if no searches have been performed.
	 * @return the BSimSearchSettings that was used in the previous search 
	 */
	public BSimSearchSettings getLastUsedSearchSettings();

	/**
	 * Initiates a BSim similar functions search.
	 * @param severCache the server to query
	 * @param settings the settings to use for the search
	 * @param functions the functions to search for similar matches
	 */
	public void search(BSimServerCache severCache, BSimSearchSettings settings,
		Set<FunctionSymbol> functions);

	/**
	 * Initiates a BSim overview search using all the functions in the program.
	 * @param severCache the server to query
	 * @param settings the settings to use for the search
	 */
	public void performOverview(BSimServerCache severCache, BSimSearchSettings settings);
}

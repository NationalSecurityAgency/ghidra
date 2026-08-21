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
package ghidra.app.services;

import ghidra.app.nav.Navigatable;
import ghidra.features.base.memsearch.gui.MemorySearchProvider;
import ghidra.features.base.memsearch.gui.SearchSettings;

/**
 * Service for invoking the {@link MemorySearchProvider}
 * @deprecated This is not a generally useful service, may go away at some point
 */
@Deprecated(since = "11.2")
public interface MemorySearchService {

	/**
	 * Creates a new memory search provider window
	 * @param navigatable the navigatable used to get bytes to search
	 * @param input the input string to search for
	 * @param settings the settings that determine how to interpret the input string
	 * @param useSelection true if the provider should automatically restrict to a selection if
	 * a selection exists in the navigatable
	 */
	public void createMemorySearchProvider(Navigatable navigatable, String input,
			SearchSettings settings, boolean useSelection);

// These method were removed because they didn't work correctly and were specific to the needs of
// one outlier plugin. The functionality has been replaced by the above method, which is also
// unlikely to be useful.

//	public void search(byte[] bytes, NavigatableActionContext context);
//
//	public void setSearchText(String maskedString);
//
//	public void setIsMnemonic(boolean isMnemonic);

}

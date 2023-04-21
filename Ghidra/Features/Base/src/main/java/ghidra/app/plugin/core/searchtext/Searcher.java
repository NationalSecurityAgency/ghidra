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
package ghidra.app.plugin.core.searchtext;

import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * Search the program text
 */
public interface Searcher {

	/**
	 * Get the next program location.
	 * @return null if there is no next program location.
	 */
	public TextSearchResult search();

	/**
	 * Set the task monitor.
	 * @param monitor monitor that allows the search to be canceled
	 */
	public void setMonitor(TaskMonitor monitor);

	/**
	 * Return the search options associated with this Searcher.
	 * @return the search option
	 */
	public SearchOptions getSearchOptions();

	/**
	 * A record object that represents a single search result
	 * 
	 * @param programLocation the program location of the search result. 
	 * @param offset the offset in the *model*'s text of the search result; this value will be from
	 *        0 to text.length(), where text is a single string for all text in the given field.
	 */
	public record TextSearchResult(ProgramLocation programLocation, int offset) {
		// stub
	}
}

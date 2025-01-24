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
package docking.widgets;

import java.util.List;

import javax.help.UnsupportedOperationException;

/**
 * A simple interface for the {@link FindDialog} so that it can work for different search clients.
 * <p>
 * The {@link CursorPosition} object used by this interface is one that implementations can extend 
 * to add extra context to use when searching.  The implementation is responsible for creating the
 * locations and these locations will later be handed back to the searcher.
 */
public interface FindDialogSearcher {

	/**
	 * The current cursor position.  Used to search for the next item.
	 * @return the cursor position.
	 */
	public CursorPosition getCursorPosition();

	/**
	 * Sets the cursor position after a successful search.
	 * @param position the cursor position.
	 */
	public void setCursorPosition(CursorPosition position);

	/**
	 * Returns the start cursor position.  This is used when a search is wrapped to start at the 
	 * beginning of the search range.
	 * @return the start position.
	 */
	public CursorPosition getStart();

	/**
	 * The end cursor position.  This is used when a search is wrapped while searching backwards to 
	 * start at the end position.
	 * @return the end position. 
	 */
	public CursorPosition getEnd();

	/**
	 * Called to signal the implementor should highlight the given search location.
	 * @param location the search result location.
	 */
	public void highlightSearchResults(SearchLocation location);

	/**
	 * Clears any active highlights.
	 */
	public void clearHighlights();

	/**
	 * Perform a search for the next item in the given direction starting at the given cursor 
	 * position.
	 * @param text the search text.
	 * @param cursorPosition the current cursor position.
	 * @param searchForward true if searching forward.
	 * @param useRegex useRegex true if the search text is a regular expression; false if the texts is
	 * literal text.
	 * @return the search result or null if no match was found.
	 */
	public SearchLocation search(String text, CursorPosition cursorPosition, boolean searchForward,
			boolean useRegex);

	/**
	 * Search for all matches.
	 * @param text the search text.
	 * @param useRegex true if the search text is a regular expression; false if the texts is
	 * literal text.
	 * @return all search results or an empty list.
	 */
	public default List<SearchLocation> searchAll(String text, boolean useRegex) {
		throw new UnsupportedOperationException("Search All is not defined for this searcher");
	}

	/**
	 * Disposes this searcher.  This does nothing by default.
	 */
	public default void dispose() {
		// stub
	}
}

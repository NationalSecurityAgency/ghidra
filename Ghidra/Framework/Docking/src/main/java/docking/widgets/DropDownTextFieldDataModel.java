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

import static ghidra.util.UserSearchUtils.*;

import java.util.List;
import java.util.regex.Pattern;

import javax.help.UnsupportedOperationException;
import javax.swing.ListCellRenderer;

import ghidra.util.UserSearchUtils;

/**
 * This interface represents all methods needed by the {@link DropDownSelectionTextField} in order
 * to search, show, manipulate and select objects.
 *
 * @param <T> The type of object that this model manipulates
 */
public interface DropDownTextFieldDataModel<T> {

	public enum SearchMode {

		/** Matches when any line of data contains the search text */
		CONTAINS("()", "Contains"),

		/** Matches when any line of data starts with the search text */
		STARTS_WITH("^", "Starts With"),

		/** Matches when any line of data contains the search text using globbing characters */
		WILDCARD("*?", "Wildcard"),

		/** Used internally */
		UNKNOWN("", "");

		private String hint;
		private String displayName;

		SearchMode(String hint, String displayName) {
			this.hint = hint;
			this.displayName = displayName;
		}

		public String getHint() {
			return hint;
		}

		public String getDisplayName() {
			return displayName;
		}

		/**
		 * Creates search pattern for the given input text.  Clients do not have to use this method
		 * and a free to create their own text matching mechanism.
		 * @param input the input for which to search
		 * @return the pattern
		 * @see UserSearchUtils
		 */
		public Pattern createPattern(String input) {
			switch (this) {
				case CONTAINS:
					return createContainsPattern(input, false, Pattern.CASE_INSENSITIVE);
				case STARTS_WITH:
					return createStartsWithPattern(input, false, Pattern.CASE_INSENSITIVE);
				case WILDCARD:
					return createContainsPattern(input, true, Pattern.CASE_INSENSITIVE);
				default:
					throw new IllegalStateException("Cannot create pattern for mode: " + this);
			}
		}
	}

	/**
	 * Returns a list of data that matches the given <code>searchText</code>.  A list is returned to
	 * allow for multiple matches.  The type of matching performed is determined by the current
	 * {@link #getSupportedSearchModes() search mode}.  If the implementation of this model does not
	 * support search modes, then it is up the the implementor to determine how matches are found.
	 * <P>
	 * Implementation Note: a client request for all data will happen using the empty string.  If
	 * your data model is sufficiently large, then you may choose to not return any data in this 
	 * case.  Smaller data sets should return all data when given the empty string
	 * 
	 * @param searchText The text used to find matches.
	 * @return a list of items matching the given text.
	 * @see #getMatchingData(String, SearchMode)
	 */
	public List<T> getMatchingData(String searchText);

	/**
	 * Returns a list of data that matches the given <code>searchText</code>.  A list is returned to
	 * allow for multiple matches.  The type of matching performed is determined by the current
	 * {@link #getSupportedSearchModes() search mode}.  If the implementation of this model does not
	 * support search modes, then it is up the the implementor to determine how matches are found.
	 * <P>
	 * Implementation Note: a client request for all data will happen using the empty string.  If
	 * your data model is sufficiently large, then you may choose to not return any data in this 
	 * case.  Smaller data sets should return all data when given the empty string
	 * 
	 * @param searchText the text used to find matches.
	 * @param searchMode the search mode to use
	 * @return a list of items matching the given text.
	 * @throws IllegalArgumentException if the given search mode is not supported 
	 * @see #getMatchingData(String, SearchMode)
	 */
	public default List<T> getMatchingData(String searchText, SearchMode searchMode) {

		// Clients that override getSupportedSearchModes() must also override this method to perform
		// the correct type of search
		if (searchMode != SearchMode.UNKNOWN) {
			throw new UnsupportedOperationException(
				"You must override this method to use search modes");
		}

		// Use the default matching data
		return getMatchingData(searchText);
	}

	/**
	 * Subclasses can override this to return all supported search modes.  The order of the modes is
	 * the order which they will cycle when requested by the user.  The first mode is the default 
	 * search mode.
	 * @return the supported search modes
	 */
	public default List<SearchMode> getSupportedSearchModes() {
		return List.of(SearchMode.UNKNOWN);
	}

	/**
	 * Returns the index in the given list of the first item that matches the given text.  For 
	 * data sets that do not allow duplicates, this is simply the index of the item that matches
	 * the text in the list.  For items that allow duplicates, the is the index of the first match.
	 * 
	 * @param data the list to search.
	 * @param text the text to match against the items in the list.
	 * @return the index in the given list of the first item that matches the given text.
	 */
	public int getIndexOfFirstMatchingEntry(List<T> data, String text);

	/**
	 * Returns the renderer to be used to paint the contents of the list returned by 
	 * {@link #getMatchingData(String)}.
	 * @return the renderer.
	 */
	public ListCellRenderer<T> getListRenderer();

	/**
	 * Returns a description for this item that gives that will be displayed along side of the
	 * {@link DropDownSelectionTextField}'s matching window. 
	 * @param value the value.
	 * @return the description.
	 */
	public String getDescription(T value);

	/**
	 * Returns the text for the given item that will be entered into the 
	 * {@link DropDownSelectionTextField} when the user makes a selection.
	 * @param value the value.
	 * @return the description.
	 */
	public String getDisplayText(T value);
}

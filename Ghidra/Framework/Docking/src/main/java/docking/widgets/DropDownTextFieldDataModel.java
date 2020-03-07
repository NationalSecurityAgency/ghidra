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

import javax.swing.ListCellRenderer;

/**
 * This interface represents all methods needed by the {@link DropDownSelectionTextField} in order
 * to search, show, manipulate and select objects.
 *
 * @param <T> The type of object that this model manipulates
 */
public interface DropDownTextFieldDataModel<T> {

	/**
	 * Returns a list of data that matches the given <code>searchText</code>.  A match typically 
	 * means a "startsWith" match.  A list is returned to allow for multiple matches.
	 * 
	 * @param searchText The text used to find matches.
	 * @return a list of items matching the given text.
	 */
	public List<T> getMatchingData(String searchText);

	/**
	 * Returns the index in the given list of the first item that matches the given text.  For 
	 * data sets that do not allow duplicates, this is simply the index of the item that matches
	 * the text in the list.  For items that allow duplicates, the is the index of the first match.
	 * 
	 * @param data the list to search
	 * @param text the text to match against the items in the list
	 * @return the index in the given list of the first item that matches the given text.
	 */
	public int getIndexOfFirstMatchingEntry(List<T> data, String text);

	/**
	 * Returns the renderer to be used to paint the contents of the list returned by 
	 * {@link #getMatchingData(String)}.
	 */
	public ListCellRenderer<T> getListRenderer();

	/**
	 * Returns a description for this item that gives that will be displayed along side of the
	 * {@link DropDownSelectionTextField}'s matching window. 
	 */
	public String getDescription(T value);

	/**
	 * Returns the text for the given item that will be entered into the 
	 * {@link DropDownSelectionTextField} when the user makes a selection.
	 */
	public String getDisplayText(T value);
}

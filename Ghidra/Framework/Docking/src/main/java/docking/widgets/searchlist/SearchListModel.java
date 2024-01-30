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
package docking.widgets.searchlist;

import java.util.List;
import java.util.function.BiPredicate;

import javax.swing.ListModel;

/**
 * Interface for the model for {@link SearchList}. It is an extension of a JList's model to add
 * the ability to group items into categories.
 *
 * @param <T> the type of data items in the search list
 */
public interface SearchListModel<T> extends ListModel<SearchListEntry<T>> {

	/**
	 * Returns the list of categories in the order they were added to the model
	 * @return the list of categories in the order they were added to the model
	 */
	public List<String> getCategories();

	/**
	 * Sets the filter for the model data to display.
	 * @param filter the BiPredicate for the model data to display which will filter based on
	 * the item and its category
	 */
	public void setFilter(BiPredicate<T, String> filter);

	/**
	 * Clean up any resources held by the model
	 */
	public void dispose();

}

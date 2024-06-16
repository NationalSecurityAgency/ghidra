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

import java.util.*;
import java.util.function.BiPredicate;

import javax.swing.AbstractListModel;
import javax.swing.ListModel;

import utility.function.Dummy;

/**
 * Default implementation of the {@link SearchListModel}. Since this model's primary purpose is 
 * to also implement the {@link ListModel}, this class extends the AbstractListModel.
 * This model's primary type is T, but it implements the list model on SearchListEntry<T> to provide
 * more information for the custom rendering that groups items into categories.
 *
 * @param <T> The type of items to display and select.
 */
public class DefaultSearchListModel<T> extends AbstractListModel<SearchListEntry<T>>
		implements SearchListModel<T> {

	// Use a LinkedHashMap here so that categories are displayed in the order they are added
	private Map<String, List<T>> dataMap = new LinkedHashMap<>();
	private List<SearchListEntry<T>> displayEntries;
	private BiPredicate<T, String> currentFilter = Dummy.biPredicate();

	@Override
	public int getSize() {
		buildEntriesIfNeeded();
		return displayEntries.size();
	}

	@Override
	public SearchListEntry<T> getElementAt(int index) {
		buildEntriesIfNeeded();
		return displayEntries.get(index);
	}

	/**
	 * Adds the list of items to the given category. If the category already exists, these items
	 * will be added to any items already associated with that cateogry.
	 * @param category the category to add the items to
	 * @param items the list of items to add to and be associated with the given category
	 */
	public void add(String category, List<T> items) {
		List<T> list = dataMap.computeIfAbsent(category, c -> new ArrayList<T>());
		list.addAll(items);
		displayEntries = null;
	}

	/**
	 * Provides a way to kick the list display to update.
	 */
	public void fireDataChanged() {
		fireContentsChanged(this, 0, getSize());
	}

	/**
	 * Removes all categories and items from this model
	 */
	public void clearData() {
		dataMap.clear();
		displayEntries = null;
	}

	@Override
	public void setFilter(BiPredicate<T, String> filter) {
		this.currentFilter = filter;
		displayEntries = null;
		rebuildDisplayItems();
		fireDataChanged();
	}

	private void buildEntriesIfNeeded() {
		if (displayEntries == null) {
			rebuildDisplayItems();
		}
	}

	@Override
	public List<String> getCategories() {
		return new ArrayList<>(dataMap.keySet());
	}

	@Override
	public void dispose() {
		dataMap = null;
		displayEntries = null;
	}

	/**
	 * Returns a list of all displayed item entries (only ones matching the current filter).
	 * @return a list of all display item entries
	 */
	public List<SearchListEntry<T>> getDisplayedItems() {
		buildEntriesIfNeeded();
		return new ArrayList<>(displayEntries);
	}

	/**
	 * Returns a list of all item entries regardless of the current filter.
	 * @return a list of all item entries
	 */
	public List<SearchListEntry<T>> getAllItems() {
		return getFilteredEntries(Dummy.biPredicate());
	}

	private void rebuildDisplayItems() {
		this.displayEntries = getFilteredEntries(currentFilter);
	}

	private List<SearchListEntry<T>> getFilteredEntries(BiPredicate<T, String> filter) {
		List<SearchListEntry<T>> entries = new ArrayList<>();

		Iterator<String> it = dataMap.keySet().iterator();
		while (it.hasNext()) {
			String category = it.next();
			List<T> list = getFilteredItems(category, filter);
			for (T value : list) {
				boolean isFirst = list.get(0) == value;
				boolean isLastInCateogry = list.get(list.size() - 1) == value;
				boolean isLastCategory = !it.hasNext();
				boolean showSeparator = isLastInCateogry && !isLastCategory;
				entries.add(new SearchListEntry<T>(value, category, isFirst, showSeparator));
			}
		}

		return entries;
	}

	private List<T> getFilteredItems(String category, BiPredicate<T, String> filter) {
		List<T> filtered = new ArrayList<>();
		List<T> list = dataMap.get(category);
		for (T value : list) {
			if (filter.test(value, category)) {
				filtered.add(value);
			}
		}
		return filtered;

	}

}

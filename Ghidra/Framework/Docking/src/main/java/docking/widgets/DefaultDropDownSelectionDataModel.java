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

import java.util.*;

import javax.swing.ListCellRenderer;

import docking.widgets.list.GListCellRenderer;
import ghidra.util.datastruct.CaseInsensitiveDuplicateStringComparator;

public class DefaultDropDownSelectionDataModel<T> implements DropDownTextFieldDataModel<T> {
	private static final char END_CHAR = '\uffff';

	protected List<T> data;
	private ObjectStringComparator comparator;
	private DataToStringConverter<T> searchConverter;
	private DataToStringConverter<T> descriptionConverter;
	private ListCellRenderer<T> renderer =
		GListCellRenderer.createDefaultCellTextRenderer(value -> searchConverter.getString(value));

	public static DefaultDropDownSelectionDataModel<String> getStringModel(List<String> strings) {
		return new DefaultDropDownSelectionDataModel<>(strings,
			DataToStringConverter.stringDataToStringConverter);
	}

	public DefaultDropDownSelectionDataModel(List<T> data,
			DataToStringConverter<T> searchConverter) {
		this(data, searchConverter, null);
	}

	public DefaultDropDownSelectionDataModel(List<T> data, DataToStringConverter<T> searchConverter,
			DataToStringConverter<T> descriptionConverter) {
		this.data = data;
		this.searchConverter = searchConverter;
		this.descriptionConverter =
			descriptionConverter != null ? descriptionConverter : searchConverter;
		this.comparator = new ObjectStringComparator();
		Collections.sort(data, comparator);
	}

	@Override
	public List<T> getMatchingData(String searchText) {
		List<?> l = data;
		int startIndex = Collections.binarySearch(l, (Object) searchText, comparator);
		int endIndex = Collections.binarySearch(l, (Object) (searchText + END_CHAR), comparator);

		// the binary search returns a negative, incremented position if there is no match in the
		// list for the given search
		if (startIndex < 0) {
			startIndex = -startIndex - 1;
		}

		if (endIndex < 0) {
			endIndex = -endIndex - 1;
		}

		return data.subList(startIndex, endIndex);
	}

	@Override
	public int getIndexOfFirstMatchingEntry(List<T> list, String text) {
		// The data are sorted such that lower-case is before upper-case and smaller length 
		// matches come before longer matches.  If we ever find a case-sensitive exact match, 
		// use that. Otherwise, keep looking for a case-insensitve exact match.  The 
		// case-insensitive match is preferred over a non-matching item.  Once we get to a 
		// non-matching item, we can quit.
		int lastPreferredMatchIndex = -1;
		for (int i = 0; i < list.size(); i++) {
			T t = list.get(i);
			String asString = searchConverter.getString(t);
			if (asString.equals(text)) {
				// an exact match is the best possible match!
				return i;
			}

			if (asString.equalsIgnoreCase(text)) {
				// keep going, but remember this location, in case we don't find any more matches
				lastPreferredMatchIndex = i;
			}
			else {
				// we've encountered a non-matching entry--nothing left to search
				return lastPreferredMatchIndex;
			}
		}

		return -1; // we only get here when the list is empty
	}

	@Override
	public ListCellRenderer<T> getListRenderer() {
		return renderer;
	}

	@Override
	public String getDescription(T value) {
		return descriptionConverter.getString(value);
	}

	@Override
	public String getDisplayText(T value) {
		return searchConverter.getString(value);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class ObjectStringComparator implements Comparator<Object> {
		Comparator<String> stringComparator = new CaseInsensitiveDuplicateStringComparator();

		@Override
		public int compare(Object o1, Object o2) {
			String s1 = getString(o1);
			String s2 = getString(o2);
			return stringComparator.compare(s1, s2);
		}

		@SuppressWarnings("unchecked")
		private String getString(Object obj) {
			if (obj instanceof String) {
				return (String) obj;
			}
			return searchConverter.getString((T) obj);
		}
	}

}

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
package ghidra.app.util;

import java.util.*;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.help.UnsupportedOperationException;
import javax.swing.ListCellRenderer;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.DropDownTextFieldDataModel;
import docking.widgets.list.GListCellRenderer;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.datastruct.CaseInsensitiveDuplicateStringComparator;

/**
 * This is the drop down text field model for namespaces.
 */
public class NamespaceDropDownModel implements DropDownTextFieldDataModel<Namespace> {
	private static final char END_CHAR = '\uffff';
	private List<Namespace> namespaces;
	private ListCellRenderer<Namespace> renderer;
	private Comparator<Namespace> comparator =
		(n1, n2) -> n1.getName().compareToIgnoreCase(n2.getName());
	private Comparator<String> stringComparator = new CaseInsensitiveDuplicateStringComparator();

	NamespaceDropDownModel() {
		renderer = GListCellRenderer.createDefaultTextRenderer(this::getListDisplay);
		setNamespaces(Collections.emptyList());
	}

	@Override
	public List<Namespace> getMatchingData(String searchText) {
		throw new UnsupportedOperationException(
			"Method no longer supported.  Instead, call getMatchingData(String, SearchMode)");
	}

	public void setNamespaces(List<Namespace> namespaces) {
		this.namespaces = namespaces;
		Collections.sort(namespaces, comparator);
	}

	private String getListDisplay(Namespace namespace) {
		StringBuilder buf = new StringBuilder(namespace.getName());
		Namespace parentNamespace = namespace.getParentNamespace();
		if (parentNamespace != null) {
			buf.append("  (");
			buf.append(parentNamespace.getName(true));
			buf.append(")");
		}
		return buf.toString();
	}

	@Override
	public List<Namespace> getMatchingData(String searchText, SearchMode searchMode) {
		if (StringUtils.isBlank(searchText)) {
			return new ArrayList<>(namespaces);
		}

		if (!getSupportedSearchModes().contains(searchMode)) {
			throw new IllegalArgumentException("Unsupported SearchMode: " + searchMode);
		}

		if (searchMode == SearchMode.STARTS_WITH) {
			return getMatchingDataStartsWith(searchText);
		}

		Pattern p = searchMode.createPattern(searchText);
		return getMatchingDataRegex(p);
	}

	private List<Namespace> getMatchingDataRegex(Pattern p) {
		List<Namespace> results = new ArrayList<>();
		for (Namespace namespace : namespaces) {
			String namespacePath = namespace.getName(true);
			Matcher m = p.matcher(namespacePath);
			if (m.matches()) {
				results.add(namespace);
			}
		}
		return results;
	}

	private List<Namespace> getMatchingDataStartsWith(String searchText) {
		MappedList<Namespace, String> list = new MappedList<>(namespaces, n -> n.getName());

		int startIndex = Collections.binarySearch(list, searchText, stringComparator);
		int endIndex = Collections.binarySearch(list, searchText + END_CHAR, stringComparator);

		// the binary search returns a negative, incremented position if there is no match in the
		// list for the given search
		if (startIndex < 0) {
			startIndex = -startIndex - 1;
		}

		if (endIndex < 0) {
			endIndex = -endIndex - 1;
		}

		return namespaces.subList(startIndex, endIndex);
	}

	@Override
	public List<SearchMode> getSupportedSearchModes() {
		return List.of(SearchMode.STARTS_WITH, SearchMode.CONTAINS, SearchMode.WILDCARD);
	}

	@Override
	public int getIndexOfFirstMatchingEntry(List<Namespace> data, String text) {
		// The data are sorted such that lower-case is before upper-case and smaller length
		// matches come before longer matches.  If we ever find a case-sensitive exact match,
		// use that. Otherwise, keep looking for a case-insensitive exact match.  The
		// case-insensitive match is preferred over a non-matching item.  Once we get to a
		// non-matching item, we can quit.
		int lastPreferredMatchIndex = -1;
		for (int i = 0; i < data.size(); i++) {
			Namespace namespace = data.get(i);
			String name = namespace.getName();
			if (name.equals(text)) {
				// an exact match is the best possible match!
				return i;
			}

			if (name.equalsIgnoreCase(text)) {
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
	public ListCellRenderer<Namespace> getListRenderer() {
		return renderer;
	}

	@Override
	public String getDescription(Namespace value) {
		return value.getName(true);
	}

	@Override
	public String getDisplayText(Namespace value) {
		return value.getName(false);
	}

	/**
	 * Provides an read-only mapped view List of type T from a List of type S.
	 * @param <S> The type of elements in the source list
	 * @param <T> The type of elements in the mapped list
	 */
	private static class MappedList<S, T> extends AbstractList<T> {
		private final List<S> sourceList;
		private final Function<S, T> transformer;

		public MappedList(List<S> sourceList, Function<S, T> transformer) {
			this.sourceList = sourceList;
			this.transformer = transformer;
		}

		@Override
		public T get(int index) {
			return transformer.apply(sourceList.get(index));
		}

		@Override
		public int size() {
			return sourceList.size();
		}
	}
}

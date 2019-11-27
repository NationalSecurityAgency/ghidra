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
package docking.widgets.filechooser;

import java.awt.Component;
import java.io.File;
import java.util.*;

import javax.swing.*;
import javax.swing.filechooser.FileSystemView;

import docking.widgets.DropDownSelectionTextField;
import docking.widgets.DropDownTextFieldDataModel;
import docking.widgets.list.GListCellRenderer;
import ghidra.util.DateUtils;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.AssertException;

/**
 * A model that allows the {@link DropDownSelectionTextField} to work with File objects.
 */
public class FileDropDownSelectionDataModel implements DropDownTextFieldDataModel<File> {

	private static final char END_CHAR = '\uffff';

	private FileSystemView fileSystemView = FileSystemView.getFileSystemView();
	private final GhidraFileChooser chooser;
	private Comparator<File> sortComparator = new FileComparator();
	private Comparator<Object> searchComparator = new FileSearchComparator();

	public FileDropDownSelectionDataModel(GhidraFileChooser chooser) {
		this.chooser = chooser;
	}

	@Override
	public String getDisplayText(File value) {
		return value.getName();
	}

	@Override
	public int getIndexOfFirstMatchingEntry(List<File> data, String text) {
		// The data are sorted such that lower-case is before upper-case and smaller length 
		// matches come before longer matches.  If we ever find a case-sensitive exact match, 
		// use that. Otherwise, keep looking for a case-insensitve exact match.  The 
		// case-insensitive match is preferred over a non-matching item.  Once we get to a 
		// non-matching item, we can quit.
		int lastPreferredMatchIndex = -1;
		for (int i = 0; i < data.size(); i++) {
			File file = data.get(i);
			String filename = file.getName();
			if (filename.equals(text)) {
				// an exact match is the best possible match!
				return i;
			}

			if (filename.equalsIgnoreCase(text)) {
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
	public ListCellRenderer<File> getListRenderer() {
		return new FileDropDownRenderer();
	}

	@Override
	public List<File> getMatchingData(String searchText) {
		if (searchText == null || searchText.length() == 0) {
			return Collections.emptyList();
		}

		File directory = chooser.getCurrentDirectory();
		File[] files = directory.listFiles();
		if (files == null) {
			return Collections.emptyList();
		}
		List<File> list = new ArrayList<>();
		for (File file : files) {
			list.add(file);
		}

		Collections.sort(list, sortComparator);

		return getMatchingSubList(searchText, searchText + END_CHAR, list);
	}

	private List<File> getMatchingSubList(String searchTextStart, String searchTextEnd,
			List<File> list) {

		int startIndex = Collections.binarySearch(list, searchTextStart, searchComparator);
		int endIndex = Collections.binarySearch(list, searchTextEnd, searchComparator);

		// the binary search returns a negative, incremented position if there is no match in the
		// list for the given search
		if (startIndex < 0) {
			startIndex = -startIndex - 1;
		}

		if (endIndex < 0) {
			endIndex = -endIndex - 1;
		}

		return list.subList(startIndex, endIndex);
	}

	@Override
	public String getDescription(File file) {
		boolean isDir = file.isDirectory();
		return "<html><table>" + "<tr><td>" + (isDir ? "Directory: " : "File: ") + "</td><td>" +
			"<b>" + HTMLUtilities.escapeHTML(file.getName()) + "</b>" + "</td></tr>" +
			"<tr><td>Size:</td><td>" + (isDir ? "0" : file.length()) + " bytes" + "</td></tr>" +
			"<tr><td>Last modified:</td><td>" +
			DateUtils.formatDateTimestamp(new Date(file.lastModified())) + "</td></tr>" +
			"</table>";
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class FileComparator implements Comparator<File> {
		@Override
		public int compare(File f1, File f2) {
			return f1.getName().compareToIgnoreCase(f2.getName());
		}
	}

	private class FileSearchComparator implements Comparator<Object> {
		@Override
		public int compare(Object o1, Object o2) {
			if (o1 instanceof File && o2 instanceof String) {
				File file = (File) o1;
				return file.getName().compareToIgnoreCase(((String) o2));
			}
			throw new AssertException("FileCompartor used to compare files against a String key!");
		}
	}

	private class FileDropDownRenderer extends GListCellRenderer<File> {

		@Override
		protected String getItemText(File file) {
			return file.getName();
		}

		@Override
		public Component getListCellRendererComponent(JList<? extends File> list, File file,
				int index, boolean isSelected, boolean cellHasFocus) {

			super.getListCellRendererComponent(list, file, index, isSelected, cellHasFocus);

			setIcon(fileSystemView.getSystemIcon(file));
			setVerticalAlignment(SwingConstants.TOP);

			return this;
		}
	}

}

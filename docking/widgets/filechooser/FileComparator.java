/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
/*
 * Created on May 18, 2006
 */
package docking.widgets.filechooser;

import ghidra.util.filechooser.GhidraFileChooserModel;

import java.io.File;
import java.util.Comparator;

class FileComparator implements Comparator<File> {
	final static int SORT_BY_NAME = 1111;
	final static int SORT_BY_SIZE = 2222;
	final static int SORT_BY_TIME = 3333;

	private GhidraFileChooserModel model;
	private int sortBy = SORT_BY_NAME;

	FileComparator(GhidraFileChooserModel model) {
		this(model, SORT_BY_NAME);
	}

	FileComparator(GhidraFileChooserModel model, int sortBy) {
		this.model = model;
		this.sortBy = sortBy;
	}

	@Override
	public int compare(File file1, File file2) {
		if (sortBy == SORT_BY_NAME || sortBy == SORT_BY_SIZE) {
			if (model.isDirectory(file1)) {
				if (model.isDirectory(file2)) {
					int value =
						file1.getAbsolutePath().compareToIgnoreCase(file2.getAbsolutePath());
					return value;
				}
				return -1; // dirs come before files
			}
			else if (model.isDirectory(file2)) {
				return 1; // files go after dirs
			}
		}
		else if (sortBy == SORT_BY_TIME) {
			if (model.isDirectory(file1)) {
				if (model.isDirectory(file2)) {
					return compare(file1.lastModified(), file2.lastModified());
				}
				return -1; // dirs come before files
			}
			else if (model.isDirectory(file2)) {
				return 1; // files go after dirs
			}
		}

		int value = 0;
		if (sortBy == SORT_BY_NAME) {
			value = file1.getName().compareToIgnoreCase(file2.getName());
		}
		else if (sortBy == SORT_BY_SIZE) {
			value = compare(file1.length(), file2.length());
		}
		else if (sortBy == SORT_BY_TIME) {
			value = compare(file1.lastModified(), file2.lastModified());
		}
		return value;
	}

	private int compare(long l1, long l2) {
		if (l1 == l2) {
			return 0;
		}

		if (l1 - l2 > 0) {
			return 1;
		}

		return -1;
	}

}

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
/*
 * Created on May 18, 2006
 */
package docking.widgets.filechooser;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.swing.AbstractListModel;

class DirectoryListModel extends AbstractListModel<File> {

	private List<File> fileList = new ArrayList<>();

	@Override
	public File getElementAt(int index) {
		return fileList.get(index);
	}

	public File set(int index, File file) {
		File oldFile = fileList.set(index, file);
		fireContentsChanged(this, index, index);
		return oldFile;
	}

	boolean contains(File file) {
		return fileList.contains(file);
	}

	void insert(File file) {
		fileList.add(file);
		int index = fileList.size() - 1;
		fireIntervalAdded(this, index, index);
	}

	void setFiles(List<File> newFileList) {
		int size = fileList.size();
		fileList.clear();
		fireIntervalRemoved(this, 0, size);
		if (newFileList.size() != 0) {
			fileList.addAll(newFileList);
			fireIntervalAdded(this, 0, fileList.size() - 1);
		}
	}

	File getFile(int index) {
		if (index >= 0 && index < fileList.size()) {
			return fileList.get(index);
		}
		return null;
	}

	void update() {
		fireContentsChanged(this, 0, getSize() - 1);
	}

	int indexOfFile(File file) {
		return fileList.indexOf(file);
	}

	public List<File> getAllFiles() {
		return new ArrayList<>(fileList);
	}

	@Override
	public int getSize() {
		return fileList.size();
	}
}

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
package ghidra.framework.model;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.store.FolderNotEmptyException;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A dummy domain folder used to stub project folder.
 * 
 * @see TestDummyDomainFile
 */
public class TestDummyDomainFolder implements DomainFolder {

	private TestDummyDomainFolder parent;
	private String folderName;
	protected List<DomainFolder> subFolders = new ArrayList<>();
	protected List<DomainFile> files = new ArrayList<>();

	public TestDummyDomainFolder(TestDummyDomainFolder parent, String name) {
		this.parent = parent;
		this.folderName = name;
	}

	public synchronized void remove(TestDummyDomainFile file) {
		files.remove(file);
	}

	@Override
	public int compareTo(DomainFolder o) {
		throw new UnsupportedOperationException();
	}

	@Override
	public synchronized String getName() {
		return folderName;
	}

	@Override
	public DomainFolder setName(String newName) throws InvalidNameException, IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProjectLocator getProjectLocator() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProjectData getProjectData() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getPathname() {
		if (parent != null) {
			String parentPathname = StringUtils.appendIfMissing(parent.getPathname(), "/");
			return parentPathname + folderName;
		}
		return "/";
	}

	@Override
	public boolean isInWritableProject() {
		throw new UnsupportedOperationException();
	}

	@Override
	public synchronized DomainFolder getParent() {
		return parent;
	}

	@Override
	public synchronized DomainFolder[] getFolders() {
		return subFolders.toArray(new DomainFolder[subFolders.size()]);
	}

	@Override
	public synchronized DomainFolder getFolder(String name) {
		return subFolders.stream().filter(f -> f.getName().equals(name)).findFirst().orElse(null);
	}

	@Override
	public synchronized DomainFile getFile(String name) {
		return files.stream().filter(f -> f.getName().equals(name)).findFirst().orElse(null);
	}

	@Override
	public synchronized boolean isEmpty() {
		return files.isEmpty() && subFolders.isEmpty();
	}

	@Override
	public synchronized DomainFile[] getFiles() {
		return files.toArray(new DomainFile[files.size()]);
	}

	@Override
	public synchronized DomainFile createFile(String name, DomainObject obj, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException {
		DomainFile file = new TestDummyDomainFile(this, name);
		files.add(file);
		return file;
	}

	@Override
	public synchronized DomainFile createFile(String name, File packFile, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public synchronized DomainFolder createFolder(String name)
			throws InvalidNameException, IOException {
		DomainFolder folder = new TestDummyDomainFolder(this, name);
		subFolders.add(folder);
		return folder;
	}

	@Override
	public synchronized void delete() throws IOException {
		if (!isEmpty()) {
			throw new FolderNotEmptyException("");
		}
		parent.remove(this);
	}

	private synchronized void remove(TestDummyDomainFolder dummyFolder) {
		subFolders.remove(dummyFolder);
	}

	@Override
	public DomainFolder moveTo(DomainFolder newParent) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DomainFolder copyTo(DomainFolder newParent, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setActive() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String toString() {
		if (parent != null) {
			return parent + "/" + folderName;
		}
		return folderName;
	}
}

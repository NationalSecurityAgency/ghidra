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
package ghidra.framework.data;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;

import javax.swing.Icon;

import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.store.FileSystem;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class LinkedGhidraSubFolder implements LinkedDomainFolder {

	private final LinkedGhidraFolder linkedRootFolder;
	private final LinkedGhidraSubFolder parent;
	private final String folderName;

	LinkedGhidraSubFolder(String folderName) {
		this.linkedRootFolder = getLinkedRootFolder();
		this.parent = null; // must override getParent()
		this.folderName = folderName;
	}

	LinkedGhidraSubFolder(LinkedGhidraSubFolder parent, String folderName) {
		this.linkedRootFolder = parent.getLinkedRootFolder();
		this.parent = parent;
		this.folderName = folderName;
	}

	/**
	 * Get the linked root folder which corresponds to a folder-link 
	 * (see {@link FolderLinkContentHandler}).
	 * @return linked root folder
	 */
	LinkedGhidraFolder getLinkedRootFolder() {
		return linkedRootFolder;
	}

	@Override
	public boolean isInWritableProject() {
		return false; // While project may be writeable this folder is not
	}

	@Override
	public DomainFolder getParent() {
		return parent;
	}

	@Override
	public String getName() {
		return folderName;
	}

	@Override
	public DomainFolder getLinkedFolder() throws IOException {
		return linkedRootFolder.getLinkedFolder(getLinkedPathname());
	}

	@Override
	public int compareTo(DomainFolder df) {
		return getName().compareToIgnoreCase(df.getName());
	}

	@Override
	public DomainFolder setName(String newName) throws InvalidNameException, IOException {
		throw new ReadOnlyException("linked folder is read only");
	}

	@Override
	public URL getSharedProjectURL() {
		URL projectURL = getLinkedRootFolder().getProjectURL();
		if (GhidraURL.isServerRepositoryURL(projectURL)) {
			String urlStr = projectURL.toExternalForm();
			if (urlStr.endsWith(FileSystem.SEPARATOR)) {
				urlStr = urlStr.substring(0, urlStr.length() - 1);
			}
			String path = getLinkedPathname();
			if (!path.endsWith(FileSystem.SEPARATOR)) {
				path += FileSystem.SEPARATOR;
			}
			try {
				return new URL(urlStr + path);
			}
			catch (MalformedURLException e) {
				// ignore
			}
		}
		return null;
	}

	@Override
	public ProjectLocator getProjectLocator() {
		return parent.getProjectLocator();
	}

	@Override
	public ProjectData getProjectData() {
		return parent.getProjectData();
	}

	@Override
	public String getPathname() {
		// pathname within project containing folder-link 
		// getParent() may return a non-linked folder
		String path = getParent().getPathname();
		if (path.length() != FileSystem.SEPARATOR.length()) {
			path += FileSystem.SEPARATOR;
		}
		path += folderName;
		return path;
	}

	/**
	 * Get the pathname of this folder within the linked-project/repository
	 * @return absolute linked folder path within the linked-project/repository
	 */
	public String getLinkedPathname() {
		String path = parent.getLinkedPathname();
		if (!path.endsWith(FileSystem.SEPARATOR)) {
			path += FileSystem.SEPARATOR;
		}
		path += folderName;
		return path;
	}

	@Override
	public LinkedGhidraSubFolder[] getFolders() {
		try {
			DomainFolder linkedFolder = getLinkedFolder();
			DomainFolder[] folders = linkedFolder.getFolders();
			LinkedGhidraSubFolder[] linkedSubFolders = new LinkedGhidraSubFolder[folders.length];
			for (int i = 0; i < folders.length; i++) {
				linkedSubFolders[i] = new LinkedGhidraSubFolder(this, folders[i].getName());
			}
			return linkedSubFolders;
		}
		catch (IOException e) {
			Msg.error(this, "Linked folder failure: " + e.getMessage());
			return new LinkedGhidraSubFolder[0];
		}
	}

	@Override
	public LinkedGhidraSubFolder getFolder(String name) {
		try {
			DomainFolder linkedFolder = getLinkedFolder();
			DomainFolder f = linkedFolder.getFolder(name);
			if (f != null) {
				return new LinkedGhidraSubFolder(this, name);
			}
		}
		catch (IOException e) {
			Msg.error(this, "Linked folder failure: " + e.getMessage());
		}
		return null;
	}

	@Override
	public DomainFile[] getFiles() {
		try {
			DomainFolder linkedFolder = getLinkedFolder();
			DomainFile[] files = linkedFolder.getFiles();
			LinkedGhidraFile[] linkedSubFolders = new LinkedGhidraFile[files.length];
			for (int i = 0; i < files.length; i++) {
				linkedSubFolders[i] = new LinkedGhidraFile(this, files[i].getName());
			}
			return linkedSubFolders;
		}
		catch (IOException e) {
			Msg.error(this, "Linked folder failure: " + e.getMessage());
			return new LinkedGhidraFile[0];
		}
	}

	/**
	 * Get the true file within this linked folder.
	 * @param name file name
	 * @return file or null if not found or error occurs
	 */
	public DomainFile getLinkedFileNoError(String name) {
		try {
			DomainFolder linkedFolder = getLinkedFolder();
			return linkedFolder.getFile(name);
		}
		catch (IOException e) {
			Msg.error(this, "Linked folder failure: " + e.getMessage());
		}
		return null;
	}

	DomainFile getLinkedFile(String name) throws IOException {
		DomainFolder linkedFolder = getLinkedFolder();
		DomainFile df = linkedFolder.getFile(name);
		if (df == null) {
			throw new FileNotFoundException("linked-file '" + name + "' not found");
		}
		return df;
	}

	@Override
	public DomainFile getFile(String name) {
		DomainFile f = getLinkedFileNoError(name);
		return f != null ? new LinkedGhidraFile(this, name) : null;
	}

	@Override
	public boolean isEmpty() {
		try {
			DomainFolder linkedFolder = getLinkedFolder();
			return linkedFolder.isEmpty();
		}
		catch (IOException e) {
			Msg.error(this, "Linked folder failure: " + e.getMessage());
			// TODO: what should we return if folder not found or error occurs?
			// True is returned to allow this method to be used to avoid continued access.
			return true;
		}
	}

	@Override
	public DomainFile createFile(String name, DomainObject obj, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException {
		throw new ReadOnlyException("linked folder is read only");
	}

	@Override
	public DomainFile createFile(String name, File packFile, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException {
		throw new ReadOnlyException("linked folder is read only");
	}

	@Override
	public DomainFolder createFolder(String name) throws InvalidNameException, IOException {
		throw new ReadOnlyException("linked folder is read only");
	}

	@Override
	public void delete() throws IOException {
		throw new ReadOnlyException("linked folder is read only");
	}

	@Override
	public DomainFolder moveTo(DomainFolder newParent) throws IOException {
		throw new ReadOnlyException("linked folder is read only");
	}

	@Override
	public DomainFolder copyTo(DomainFolder newParent, TaskMonitor monitor)
			throws IOException, CancelledException {
		DomainFolder linkedFolder = getLinkedFolder();
		return linkedFolder.copyTo(newParent, monitor);
	}

	@Override
	public DomainFile copyToAsLink(DomainFolder newParent) throws IOException {
		DomainFolder linkedFolder = getLinkedFolder();
		return linkedFolder.copyToAsLink(newParent);
	}

	@Override
	public void setActive() {
		// do nothing
	}

	@Override
	public String toString() {
		return "LinkedGhidraSubFolder: " + getPathname();
	}

	@Override
	public Icon getIcon(boolean isOpen) {
		return isOpen ? OPEN_FOLDER_ICON : CLOSED_FOLDER_ICON;
	}

}

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

/**
 * {@code LinkedGhidraSubFolder} corresponds to a {@link DomainFolder} contained within a
 * {@link LinkedGhidraFolder} or another {@code LinkedGhidraSubFolder}.
 */
class LinkedGhidraSubFolder implements LinkedDomainFolder {

	private final LinkedGhidraFolder linkedRootFolder;
	private final LinkedGhidraSubFolder parent;
	private final String folderName;

	/**
	 * Construct root-linked-folder based on the name of a folder-link link-file.
	 * @param linkFileName name of link-file which represents a folder-link
	 */
	LinkedGhidraSubFolder(String linkFileName) {
		this.linkedRootFolder = getLinkedRootFolder();
		this.parent = null; // must override getParent()
		this.folderName = linkFileName;
	}

	/**
	 * Construct a linked-folder child
	 * @param parent parent folder within a linked-folder hierarchy
	 * @param folderName folder name
	 */
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
	public boolean isExternal() {
		return linkedRootFolder.isExternal();
	}

	@Override
	public boolean isInWritableProject() {
		return linkedRootFolder.isInWritableProject();
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
	public DomainFolder getRealFolder() throws IOException {
		return linkedRootFolder.getRealFolder(getLinkedPathname());
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof LinkedGhidraSubFolder other)) {
			return false;
		}
		return folderName.equals(other.folderName) && parent.equals(other.parent);
	}

	@Override
	public int hashCode() {
		return getPathname().hashCode();
	}

	@Override
	public int compareTo(DomainFolder df) {
		return getName().compareToIgnoreCase(df.getName());
	}

	@Override
	public boolean isSame(DomainFolder folder) {

		// NOTE: This project check relates to the outermost containing project
		// and not the project that may be referenenced by a link.
		if (!getProjectLocator().equals(folder.getProjectLocator()) &&
			!SystemUtilities.isEqual(getProjectData().getSharedProjectURL(),
				folder.getProjectData().getSharedProjectURL())) {
			// Containing project/repository appears to be unrelated
			return false;
		}

		return getPathname().equals(folder.getPathname());
	}

	@Override
	public boolean isSameOrAncestor(DomainFolder folder) {

		// NOTE: This project check relates to the outermost containing project
		// and not the project that may be referenenced by a link.
		if (!getProjectLocator().equals(folder.getProjectLocator()) &&
			!SystemUtilities.isEqual(getProjectData().getSharedProjectURL(),
				folder.getProjectData().getSharedProjectURL())) {
			// Containing project/repository appears to be unrelated
			return false;
		}

		String pathname = getPathname();

		DomainFolder f = folder;
		while (f != null) {
			if (f == this || pathname.equals(f.getPathname())) {
				return true;
			}
			f = f.getParent();
		}
		return false;
	}

	@Override
	public DomainFolder setName(String newName) throws InvalidNameException, IOException {
		DomainFolder linkedFolder = getRealFolder();
		String name = linkedFolder.setName(newName).getName();
		return parent.getFolder(name);
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
	public URL getLocalProjectURL() {
		ProjectLocator projectLocator = parent.getProjectLocator();
		if (!projectLocator.isTransient()) {
			return GhidraURL.makeURL(projectLocator, getPathname(), null);
		}
		return null;
	}

	@Override
	public ProjectLocator getProjectLocator() {
		return parent.getProjectLocator();
	}

	@Override
	public ProjectData getLinkedProjectData() throws IOException {
		return linkedRootFolder.getLinkedProjectData();
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

	@Override
	public String getLinkedPathname() {
		return parent.getLinkedPathname(folderName);
	}

	final String getLinkedPathname(String childName) {
		String path = getLinkedPathname();
		if (!path.endsWith(FileSystem.SEPARATOR)) {
			path += FileSystem.SEPARATOR;
		}
		path += childName;
		return path;
	}

	@Override
	public LinkedGhidraSubFolder[] getFolders() {
		try {
			DomainFolder linkedFolder = getRealFolder();
			DomainFolder[] folders = linkedFolder.getFolders();
			LinkedGhidraSubFolder[] linkedSubFolders = new LinkedGhidraSubFolder[folders.length];
			for (int i = 0; i < folders.length; i++) {
				linkedSubFolders[i] = new LinkedGhidraSubFolder(this, folders[i].getName());
			}
			return linkedSubFolders;
		}
		catch (IOException e) {
			Msg.error(this, "Linked folder failure '" + this + "': " + e.getMessage());
			return new LinkedGhidraSubFolder[0];
		}
	}

	@Override
	public LinkedGhidraSubFolder getFolder(String name) {
		try {
			DomainFolder linkedFolder = getRealFolder();
			DomainFolder f = linkedFolder.getFolder(name);
			if (f != null) {
				return new LinkedGhidraSubFolder(this, name);
			}
		}
		catch (IOException e) {
			Msg.error(this, "Linked folder failure '" + this + "': " + e.getMessage());
		}
		return null;
	}

	@Override
	public DomainFile[] getFiles() {
		try {
			DomainFolder linkedFolder = getRealFolder();
			DomainFile[] files = linkedFolder.getFiles();
			LinkedGhidraFile[] linkedSubFolders = new LinkedGhidraFile[files.length];
			for (int i = 0; i < files.length; i++) {
				linkedSubFolders[i] = new LinkedGhidraFile(this, files[i].getName());
			}
			return linkedSubFolders;
		}
		catch (IOException e) {
			Msg.error(this, "Linked folder failure '" + this + "': " + e.getMessage());
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
			DomainFolder linkedFolder = getRealFolder();
			return linkedFolder.getFile(name);
		}
		catch (IOException e) {
			// Ignore
		}
		return null;
	}

	DomainFile getLinkedFile(String name) throws IOException {
		DomainFolder linkedFolder = getRealFolder();
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
			DomainFolder linkedFolder = getRealFolder();
			return linkedFolder.isEmpty();
		}
		catch (IOException e) {
			Msg.error(this, "Linked folder failure '" + this + "': " + e.getMessage());
			// TODO: what should we return if folder not found or error occurs?
			// True is returned to allow this method to be used to avoid continued access.
			return true;
		}
	}

	@Override
	public DomainFile createFile(String name, DomainObject obj, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException {
		DomainFolder linkedFolder = getRealFolder();
		return linkedFolder.createFile(name, obj, monitor);
	}

	@Override
	public DomainFile createFile(String name, File packFile, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException {
		DomainFolder linkedFolder = getRealFolder();
		return linkedFolder.createFile(name, packFile, monitor);
	}

	@Override
	public DomainFile createLinkFile(ProjectData sourceProjectData, String pathname,
			boolean makeRelative, String linkFilename, LinkHandler<?> lh) throws IOException {
		DomainFolder linkedFolder = getRealFolder();
		return linkedFolder.createLinkFile(sourceProjectData, pathname, makeRelative, linkFilename,
			lh);
	}

	@Override
	public DomainFile createLinkFile(String ghidraUrl, String linkFilename, LinkHandler<?> lh)
			throws IOException {
		DomainFolder linkedFolder = getRealFolder();
		return linkedFolder.createLinkFile(ghidraUrl, linkFilename, lh);
	}

	@Override
	public DomainFolder createFolder(String name) throws InvalidNameException, IOException {
		DomainFolder linkedFolder = getRealFolder();
		DomainFolder child = linkedFolder.createFolder(name);
		return new LinkedGhidraSubFolder(parent, child.getName());
	}

	@Override
	public void delete() throws IOException {
		DomainFolder linkedFolder = getRealFolder();
		linkedFolder.delete();
	}

	@Override
	public DomainFolder moveTo(DomainFolder newParent) throws IOException {
		DomainFolder linkedFolder = getRealFolder();
		return linkedFolder.moveTo(newParent);
	}

	@Override
	public DomainFolder copyTo(DomainFolder newParent, TaskMonitor monitor)
			throws IOException, CancelledException {
		DomainFolder linkedFolder = getRealFolder();
		return linkedFolder.copyTo(newParent, monitor);
	}

	@Override
	public DomainFile copyToAsLink(DomainFolder newParent, boolean relative) throws IOException {
		DomainFolder linkedFolder = getRealFolder();
		return linkedFolder.copyToAsLink(newParent, relative);
	}

	@Override
	public void setActive() {
		try {
			DomainFolder linkedFolder = getRealFolder();
			linkedFolder.setActive();
		}
		catch (IOException e) {
			// ignore
		}
	}

	@Override
	public String toString() {
		String str = parent.toString();
		if (!str.endsWith("/")) {
			str += "/";
		}
		str += getName();
		return str;
	}

	@Override
	public Icon getIcon(boolean isOpen) {
		return isOpen ? OPEN_FOLDER_ICON : CLOSED_FOLDER_ICON;
	}

}

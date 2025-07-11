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
import java.util.List;

import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GhidraFolder implements DomainFolder {

	private DefaultProjectData projectData;
	private LocalFileSystem fileSystem;
	private FileSystem versionedFileSystem;
	private DomainFolderChangeListener listener;

	private GhidraFolder parent;
	private String name;

	GhidraFolder(DefaultProjectData projectData, DomainFolderChangeListener listener) {
		this.projectData = projectData;
		this.fileSystem = projectData.getLocalFileSystem();
		this.versionedFileSystem = projectData.getVersionedFileSystem();
		this.listener = listener;
		this.name = FileSystem.SEPARATOR;
	}

	GhidraFolder(GhidraFolder parent, String name) {
		this.parent = parent;
		this.name = name;

		this.projectData = parent.getProjectData();
		this.fileSystem = parent.getLocalFileSystem();
		this.versionedFileSystem = parent.getVersionedFileSystem();
		this.listener = parent.getChangeListener();
	}

	LocalFileSystem getLocalFileSystem() {
		return fileSystem;
	}

	FileSystem getVersionedFileSystem() {
		return versionedFileSystem;
	}

	LocalFileSystem getUserFileSystem() {
		return projectData.getUserFileSystem();
	}

	DomainFolderChangeListener getChangeListener() {
		return listener;
	}

	GhidraFileData getFileData(String fileName) throws FileNotFoundException, IOException {
		GhidraFileData fileData = getFolderData().getFileData(fileName, false);
		if (fileData == null) {
			throw new FileNotFoundException("file " + getPathname(fileName) + " not found");
		}
		return fileData;
	}

	GhidraFolderData getFolderData() throws FileNotFoundException {
		if (parent == null) {
			return projectData.getRootFolderData();
		}
		GhidraFolderData folderData = parent.getFolderData().getFolderData(name, false);
		if (folderData == null) {
			throw new FileNotFoundException("folder " + getPathname() + " not found");
		}
		return folderData;
	}

	/**
	 * Create folder hierarchy in local filesystem if it does not already exist
	 * @param folderName name of new folder
	 * @return folder data
	 * @throws IOException error while creating folder
	 */
	private GhidraFolderData createFolderData(String folderName) throws IOException {
		synchronized (fileSystem) {
			GhidraFolderData parentData =
				parent == null ? projectData.getRootFolderData() : createFolderData();
			GhidraFolderData folderData = parentData.getFolderData(folderName, false);
			if (folderData == null) {
				try {
					folderData = parentData.createFolder(folderName);
				}
				catch (InvalidNameException e) {
					throw new IOException(e);
				}
			}
			return folderData;
		}
	}

	private GhidraFolderData createFolderData() throws IOException {
		GhidraFolderData rootFolderData = projectData.getRootFolderData();
		if (parent == null) {
			return rootFolderData;
		}
		return parent.createFolderData(name);
	}

	/**
	 * Refresh folder data - used for testing only
	 * @throws IOException if an IO error occurs
	 */
	void refreshFolderData() throws IOException {
		getFolderData().refresh(false, true, TaskMonitor.DUMMY);
	}

	@Override
	public int compareTo(DomainFolder df) {
		return name.compareToIgnoreCase(df.getName());
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public GhidraFolder setName(String newName) throws InvalidNameException, IOException {
		return getFolderData().setName(newName);
	}

	@Override
	public ProjectLocator getProjectLocator() {
		return projectData.getProjectLocator();
	}

	@Override
	public DefaultProjectData getProjectData() {
		return projectData;
	}

	String getPathname(String childName) {
		String path = getPathname();
		if (path.length() != FileSystem.SEPARATOR.length()) {
			path += FileSystem.SEPARATOR;
		}
		path += childName;
		return path;
	}

	@Override
	public String getPathname() {
		if (parent == null) {
			return FileSystem.SEPARATOR;
		}
		String path = parent.getPathname();
		if (path.length() != FileSystem.SEPARATOR.length()) {
			path += FileSystem.SEPARATOR;
		}
		path += name;
		return path;
	}

	@Override
	public URL getSharedProjectURL() {
		URL projectURL = projectData.getSharedProjectURL();
		if (projectURL == null) {
			return null;
		}
		try {
			// Direct URL construction done so that ghidra protocol extension may be supported
			String urlStr = projectURL.toExternalForm();
			if (urlStr.endsWith(FileSystem.SEPARATOR)) {
				urlStr = urlStr.substring(0, urlStr.length() - 1);
			}
			String path = getPathname();
			if (!path.endsWith(FileSystem.SEPARATOR)) {
				path += FileSystem.SEPARATOR;
			}
			urlStr += path;
			return new URL(urlStr);
		}
		catch (MalformedURLException e) {
			return null;
		}
	}

	@Override
	public URL getLocalProjectURL() {
		ProjectLocator projectLocator = projectData.getProjectLocator();
		if (!projectLocator.isTransient()) {
			return GhidraURL.makeURL(projectLocator, getPathname(), null);
		}
		return null;
	}

	@Override
	public boolean isInWritableProject() {
		return !fileSystem.isReadOnly();
	}

	@Override
	public DomainFolder getParent() {
		return parent;
	}

	@Override
	public GhidraFolder[] getFolders() {
		synchronized (fileSystem) {
			try {
				GhidraFolderData folderData = getFolderData();
				List<String> folderNames = folderData.getFolderNames();
				int count = folderNames.size();
				GhidraFolder[] folders = new GhidraFolder[count];
				for (int i = 0; i < count; i++) {
					folders[i] = new GhidraFolder(this, folderNames.get(i));
				}
				return folders;
			}
			catch (FileNotFoundException e) {
				return new GhidraFolder[0];
			}
		}
	}

	@Override
	public GhidraFolder getFolder(String folderName) {
		synchronized (fileSystem) {
			try {
				GhidraFolderData folderData = getFolderData();
				return folderData.getDomainFolder(folderName);
			}
			catch (FileNotFoundException e) {
				// ignore
			}
			return null;
		}
	}

	@Override
	public boolean isEmpty() {
		synchronized (fileSystem) {
			try {
				GhidraFolderData folderData = getFolderData();
				return folderData.isEmpty();
			}
			catch (FileNotFoundException e) {
				// TODO: what should we return if folder not found or error occurs?
				// True is returned to allow this method to be used to avoid continued access.
				return true;
			}
		}
	}

	@Override
	public GhidraFile[] getFiles() {
		synchronized (fileSystem) {
			try {
				GhidraFolderData folderData = getFolderData();
				List<String> fileNames = folderData.getFileNames();
				int count = fileNames.size();
				GhidraFile[] files = new GhidraFile[count];
				for (int i = 0; i < count; i++) {
					files[i] = new GhidraFile(this, fileNames.get(i));
				}
				return files;
			}
			catch (FileNotFoundException e) {
				return new GhidraFile[0];
			}
		}
	}

	@Override
	public GhidraFile getFile(String fileName) {
		synchronized (fileSystem) {
			GhidraFolderData folderData;
			try {
				folderData = getFolderData();
			}
			catch (FileNotFoundException e) {
				return null; // exception occurs if this folder has been deleted.
			}

			try {
				if (folderData.containsFile(fileName)) {
					return new GhidraFile(this, fileName);
				}
			}
			catch (IOException e) {
				Msg.error(this, "file error for " + getPathname(fileName), e);
			}
			return null;
		}
	}

	@Override
	public DomainFile createFile(String fileName, DomainObject obj, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException {
		return createFolderData().createFile(fileName, obj,
			monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	@Override
	public DomainFile createFile(String fileName, File packFile, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException {
		return createFolderData().createFile(fileName, packFile,
			monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	@Override
	public DomainFile createLinkFile(ProjectData sourceProjectData, String pathname,
			boolean makeRelative, String linkFilename, LinkHandler<?> lh) throws IOException {
		return createFolderData().createLinkFile(sourceProjectData, pathname, makeRelative,
			linkFilename, lh);
	}

	@Override
	public DomainFile createLinkFile(String ghidraUrl, String linkFilename, LinkHandler<?> lh)
			throws IOException {
		return createFolderData().createLinkFile(ghidraUrl, linkFilename, lh);
	}

	@Override
	public GhidraFolder createFolder(String folderName) throws InvalidNameException, IOException {
		return createFolderData().createFolder(folderName).getDomainFolder();
	}

	@Override
	public void delete() throws IOException {
		try {
			getFolderData().delete();
		}
		catch (FileNotFoundException e) {
			// ignore
		}
	}

	static GhidraFolder getDestinationFolder(DomainFolder newParent) throws IOException {

		while (newParent instanceof LinkedDomainFolder linkedFolder) {

			if (!linkedFolder.isInWritableProject()) {
				throw new IOException("Destination folder is not within writable project");
			}

			// Find real folder - we may have multiple levels of linking
			// This should only be done within the same writable project
			newParent = linkedFolder.getRealFolder();

		}

		if (!newParent.isInWritableProject() || !(newParent instanceof GhidraFolder ghidraFolder)) {
			throw new IOException("Destination folder is not within writable project");
		}

		return ghidraFolder;
	}

	@Override
	public GhidraFolder moveTo(DomainFolder newParent) throws IOException {
		if (parent == null) {
			throw new UnsupportedOperationException("root folder may not be moved");
		}

		if (getProjectData() != newParent.getProjectData() || !isInWritableProject()) {
			throw new IOException("Move only supported within the same writable project");
		}

		GhidraFolder newGhidraParent = getDestinationFolder(newParent);

		return getFolderData().moveTo(newGhidraParent.getFolderData());
	}

	@Override
	public GhidraFolder copyTo(DomainFolder newParent, TaskMonitor monitor)
			throws IOException, CancelledException {

		GhidraFolder newGhidraParent = getDestinationFolder(newParent);

		return getFolderData().copyTo(newGhidraParent.getFolderData(),
			monitor != null ? monitor : TaskMonitor.DUMMY);
	}

	@Override
	public DomainFile copyToAsLink(DomainFolder newParent, boolean relative) throws IOException {

		GhidraFolder newGhidraParent = getDestinationFolder(newParent);

		return getFolderData().copyToAsLink(newGhidraParent.getFolderData(), relative);
	}

	/**
	 * ** Used for testing **
	 * Check for existance of private folder
	 * @return true if private folder exists else false
	 */
	boolean privateExists() {
		try {
			return getFolderData().privateExists();
		}
		catch (FileNotFoundException e) {
			return false;
		}
	}

	/**
	 * ** Used for testing **
	 * Check for existance of versioned/shared folder
	 * @return true if versioned/shared folder exists else false
	 */
	boolean sharedExists() {
		try {
			return getFolderData().sharedExists();
		}
		catch (FileNotFoundException e) {
			return false;
		}
	}

	@Override
	public void setActive() {
		listener.domainFolderSetActive(this);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof GhidraFolder other)) {
			return false;
		}
		if (projectData != other.projectData) {
			return false;
		}
		return getPathname().equals(other.getPathname());
	}

	@Override
	public boolean isSameOrAncestor(DomainFolder folder) {

		if (!getProjectLocator().equals(folder.getProjectLocator()) &&
			!SystemUtilities.isEqual(projectData.getSharedProjectURL(),
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
	public boolean isSame(DomainFolder folder) {

		if (!getProjectLocator().equals(folder.getProjectLocator()) &&
			!SystemUtilities.isEqual(projectData.getSharedProjectURL(),
				folder.getProjectData().getSharedProjectURL())) {
			// Containing project/repository appears to be unrelated
			return false;
		}

		return getPathname().equals(folder.getPathname());
	}

	@Override
	public int hashCode() {
		return getPathname().hashCode();
	}

	@Override
	public String toString() {
		ProjectLocator projectLocator = projectData.getProjectLocator();
		if (projectLocator.isTransient()) {
			return projectData.getProjectLocator().getName() + getPathname();
		}
		return projectData.getProjectLocator().getName() + ":" + getPathname();
	}

}

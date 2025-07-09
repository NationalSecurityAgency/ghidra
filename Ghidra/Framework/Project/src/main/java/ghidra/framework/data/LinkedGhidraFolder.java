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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;

import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.store.FileSystem;
import ghidra.util.InvalidNameException;

/**
 * {@code LinkedGhidraFolder} provides the base {@link LinkedDomainFolder} implementation which
 * corresponds to a project folder-link (see {@link FolderLinkContentHandler}).
 */
public class LinkedGhidraFolder extends LinkedGhidraSubFolder {

	public static Icon FOLDER_LINK_CLOSED_ICON =
		new GIcon("icon.content.handler.linked.folder.closed");
	public static Icon FOLDER_LINK_OPEN_ICON = new GIcon("icon.content.handler.linked.folder.open");

	private final DomainFile folderLinkFile;

	// Linked folder established using either a URL or a folder
	private final URL linkedFolderUrl;
	private final DomainFolder linkedFolder;
	private final String linkedPathname;
	private final URL projectUrl;

	private boolean offline = false; // allow single failure

	/**
	 * Construct a linked-folder which is linked via a Ghidra URL.
	 * <P>
	 * NOTE: An active project is required as conveyed by {@link AppInfo#getActiveProject()}
	 * which will take ownership of any project view which is required.  This should be pre-checked
	 * since an error will occur if there is no active project at the time the link is followed.
	 * 
	 * @param folderLinkFile link-file which corresponds to a linked-folder 
	 * (see {@link LinkFileInfo#isFolderLink()}).
	 * @param linkedFolderUrl linked folder URL
	 */
	LinkedGhidraFolder(DomainFile folderLinkFile, URL linkedFolderUrl) {
		super(folderLinkFile.getName());

		if (!GhidraURL.isServerRepositoryURL(linkedFolderUrl) &&
			!GhidraURL.isLocalProjectURL(linkedFolderUrl)) {
			throw new IllegalArgumentException("Invalid Ghidra URL: " + linkedFolderUrl);
		}

		this.folderLinkFile = folderLinkFile;

		this.linkedFolderUrl = linkedFolderUrl;
		this.linkedFolder = null;

		String pathname = GhidraURL.getProjectPathname(linkedFolderUrl);
		if (!FileSystem.SEPARATOR.equals(pathname) && pathname.endsWith(FileSystem.SEPARATOR)) {
			// avoid trailing path separator except on root pathname
			pathname = pathname.substring(0, pathname.length() - 1);
		}
		linkedPathname = pathname;
		projectUrl = GhidraURL.getProjectURL(linkedFolderUrl);
	}

	/**
	 * Construct a linked-folder which is linked to another folder within the associated 
	 * {@link #getProjectData() project data} instance.
	 * 
	 * @param folderLinkFile link-file which corresponds to a linked-folder 
	 * (see {@link LinkFileInfo#isFolderLink()}).
	 * @param linkedFolder locally-linked folder within same project
	 */
	LinkedGhidraFolder(DomainFile folderLinkFile, DomainFolder linkedFolder) {
		super(folderLinkFile.getName());

		this.folderLinkFile = folderLinkFile;

		this.linkedFolder = linkedFolder;
		this.linkedFolderUrl = null;

		linkedPathname = linkedFolder.getPathname();

		projectUrl = linkedFolder.getProjectLocator().getURL();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof LinkedGhidraFolder other)) {
			return false;
		}
		return linkedPathname.equals(other.linkedPathname) &&
			folderLinkFile.equals(other.folderLinkFile);
	}

	@Override
	public boolean isExternal() {
		return linkedFolderUrl != null;
	}

	/**
	 * Get the Ghidra URL of the project/repository folder referenced by this object
	 * @return Ghidra URL of the project/repository folder referenced by this object
	 */
	public URL getProjectURL() {
		return projectUrl;
	}

	@Override
	LinkedGhidraFolder getLinkedRootFolder() {
		return this;
	}

	@Override
	public boolean isInWritableProject() {
		return linkedFolder != null && linkedFolder.isInWritableProject();
	}

	@Override
	public ProjectData getLinkedProjectData() throws IOException {
		// NOTE: The offline tracking is done to avoid repeatedly prompting for a connection
		// password.  Only one connect attempt per instance will be performed.
		ProjectData projectData;
		if (linkedFolder != null) {
			projectData = linkedFolder.getProjectData();
		}
		else {
			// Handle GhidraURL linkages
			Project activeProject = AppInfo.getActiveProject();
			if (activeProject == null) {
				offline = true;
				throw new IOException("active project not found");
			}

			URL url = getProjectURL();
			projectData = activeProject.getProjectData(url);
			if (projectData == null && !offline) {
				offline = true;
				projectData = activeProject.addProjectView(url, false);
				if (projectData != null) {
					offline = false;
					RepositoryAdapter repository = projectData.getRepository();
					if (repository != null && !repository.isConnected()) {
						// User chose not to connect - don't force them
						offline = true;
					}
				}
			}
			if (projectData == null) {
				throw new FileNotFoundException("failed to add project view: " + url);
			}
		}
		return projectData;
	}

	synchronized DomainFolder getRealFolder(String linkedPath) throws IOException {
		ProjectData projectData = getLinkedProjectData();
		DomainFolder folder = projectData.getFolder(linkedPath);
		if (folder == null) {
			RepositoryAdapter repository = projectData.getRepository();
			if (repository != null) {
				if (!offline && !repository.isConnected()) {
					repository.connect();
					if (!repository.isConnected()) {
						offline = true;
						throw new FileNotFoundException("linked project/repository not connected");
					}
					folder = projectData.getFolder(linkedPath);
				}
			}
			if (folder == null) {
				String notConnectedMsg = offline ? " (not connected)" : "";
				throw new FileNotFoundException("folder not found" + notConnectedMsg);
			}
		}
		return folder;
	}

	@Override
	public String getLinkedPathname() {
		return linkedPathname;
	}

	@Override
	public DomainFolder getRealFolder() throws IOException {
		return getRealFolder(linkedPathname);
	}

	@Override
	public ProjectLocator getProjectLocator() {
		return folderLinkFile.getProjectLocator();
	}

	@Override
	public ProjectData getProjectData() {
		return folderLinkFile.getParent().getProjectData();
	}

	@Override
	public DomainFolder getParent() {
		return folderLinkFile.getParent();
	}

	@Override
	public DomainFolder setName(String newName) throws InvalidNameException, IOException {
		DomainFile linkFile = folderLinkFile.setName(newName);
		if (linkedFolder != null) {
			return new LinkedGhidraFolder(linkFile, linkedFolder);
		}
		return new LinkedGhidraFolder(linkFile, linkedFolderUrl);
	}

	@Override
	public String toString() {
		if (linkedFolder != null) {
			return "->" + getLinkedPathname();
		}
		return "->" + linkedFolderUrl.toString();
	}

	@Override
	public Icon getIcon(boolean isOpen) {
		return isOpen ? FOLDER_LINK_OPEN_ICON : FOLDER_LINK_CLOSED_ICON;
	}

	@Override
	public boolean isLinked() {
		return true;
	}

	/**
	 * Determine if this linked-folder corresponds to an external URL linkage and not an internal 
	 * project linkage.
	 * @return true if linked based on external URL
	 */
	public boolean isUrlLinked() {
		if (linkedFolderUrl != null) {
			return true;
		}
		if (linkedFolder instanceof LinkedGhidraFolder lf) {
			return lf.isUrlLinked();
		}
		return false;
	}
}

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
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.store.FileSystem;

/**
 * {@code LinkedGhidraFolder} provides the base {@link LinkedDomainFolder} implementation which
 * corresponds to a project folder-link (see {@link FolderLinkContentHandler}).
 */
public class LinkedGhidraFolder extends LinkedGhidraSubFolder {

	public static Icon FOLDER_LINK_CLOSED_ICON =
		new GIcon("icon.content.handler.linked.folder.closed");
	public static Icon FOLDER_LINK_OPEN_ICON =
		new GIcon("icon.content.handler.linked.folder.open");

	private final Project activeProject;
	private final DomainFolder localParent;
	private final URL folderUrl;

	private String linkedPathname;

	private URL projectUrl;

	/**
	 * Construct a linked-folder.
	 * @param activeProject active project responsible for linked project life-cycle management.
	 * @param localParent local domain folder which contains folder-link or corresponds directly to
	 * folder-link (name=null).
	 * @param linkFilename folder-link filename
	 * @param folderUrl linked folder URL
	 */
	LinkedGhidraFolder(Project activeProject, DomainFolder localParent, String linkFilename,
			URL folderUrl) {
		super(linkFilename);

		if (!GhidraURL.isServerRepositoryURL(folderUrl) &&
			!GhidraURL.isLocalProjectURL(folderUrl)) {
			throw new IllegalArgumentException("Invalid Ghidra URL: " + folderUrl);
		}

		this.activeProject = activeProject;
		this.localParent = localParent;
		this.folderUrl = folderUrl;

		linkedPathname = GhidraURL.getProjectPathname(folderUrl);
		if (linkedPathname.length() > 0 && linkedPathname.endsWith(FileSystem.SEPARATOR)) {
			linkedPathname = linkedPathname.substring(0, linkedPathname.length() - 1);
		}
	}

	/**
	 * Get the Ghidra URL associated with this linked folder's project or repository
	 * @return Ghidra URL associated with this linked folder's project or repository
	 */
	public URL getProjectURL() {
		if (projectUrl == null) {
			projectUrl = GhidraURL.getProjectURL(folderUrl);
		}
		return projectUrl;
	}

	LinkedGhidraFolder getLinkedRootFolder() {
		return this;
	}

	DomainFolder getLinkedFolder(String linkedPath) throws IOException {

		ProjectData projectData = activeProject.addProjectView(getProjectURL(), false);
		if (projectData == null) {
			throw new FileNotFoundException();
		}

		DomainFolder folder = projectData.getFolder(linkedPath);
		if (folder == null) {
			throw new FileNotFoundException(folderUrl.toExternalForm());
		}
		return folder;
	}

	@Override
	public String getLinkedPathname() {
		return linkedPathname;
	}

	@Override
	public ProjectLocator getProjectLocator() {
		return activeProject.getProjectLocator();
	}

	@Override
	public ProjectData getProjectData() {
		return activeProject.getProjectData();
	}

	@Override
	public DomainFolder getParent() {
		return localParent;
	}

	@Override
	public String toString() {
		return "LinkedGhidraFolder: " + getPathname();
	}

	@Override
	public Icon getIcon(boolean isOpen) {
		return isOpen ? FOLDER_LINK_OPEN_ICON : FOLDER_LINK_CLOSED_ICON;
	}

	@Override
	public boolean isLinked() {
		return true;
	}
}

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

import java.io.IOException;
import java.net.URL;

import javax.swing.Icon;

import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.store.FileSystem;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@code FolderLinkContentHandler} provide folder-link support.  
 * Implementation relies on {@link AppInfo#getActiveProject()} to provide life-cycle 
 * management for related transient-projects opened while following folder-links. 
 */
public class FolderLinkContentHandler extends LinkHandler<NullFolderDomainObject> {

	public static FolderLinkContentHandler INSTANCE = new FolderLinkContentHandler();

	public static final String FOLDER_LINK_CONTENT_TYPE = "FolderLink";

	@Override
	public long createFile(FileSystem fs, FileSystem userfs, String path, String name,
			DomainObject obj, TaskMonitor monitor)
			throws IOException, InvalidNameException, CancelledException {
		if (!(obj instanceof URLLinkObject)) {
			throw new IOException("Unsupported domain object: " + obj.getClass().getName());
		}
		return createFile((URLLinkObject) obj, FOLDER_LINK_CONTENT_TYPE, fs, path, name,
			monitor);
	}

	@Override
	public String getContentType() {
		return FOLDER_LINK_CONTENT_TYPE;
	}

	@Override
	public String getContentTypeDisplayString() {
		return FOLDER_LINK_CONTENT_TYPE;
	}

	@Override
	public Class<NullFolderDomainObject> getDomainObjectClass() {
		return NullFolderDomainObject.class; // special case since link corresponds to a Domain Folder
	}

	@Override
	public Icon getIcon() {
		return DomainFolder.CLOSED_FOLDER_ICON;
	}

	@Override
	public String getDefaultToolName() {
		return null;
	}

	/**
	 * Get linked domain folder
	 * @param folderLinkFile folder-link file.
	 * @return {@link LinkedGhidraFolder} referenced by specified folder-link file or null if 
	 * folderLinkFile content type is not {@value #FOLDER_LINK_CONTENT_TYPE}.
	 * @throws IOException if an IO or folder item access error occurs
	 */
	public static LinkedGhidraFolder getReadOnlyLinkedFolder(DomainFile folderLinkFile)
			throws IOException {

		if (!FOLDER_LINK_CONTENT_TYPE.equals(folderLinkFile.getContentType())) {
			return null;
		}

		URL url = getURL(folderLinkFile);

		Project activeProject = AppInfo.getActiveProject();
		GhidraFolder parent = ((GhidraFile) folderLinkFile).getParent();
		return new LinkedGhidraFolder(activeProject, parent, folderLinkFile.getName(), url);
	}

}

/**
 * Dummy domain object to satisfy {@link FolderLinkContentHandler#getDomainObjectClass()}
 */
final class NullFolderDomainObject extends DomainObjectAdapterDB {
	private NullFolderDomainObject() {
		// this object may not be instantiated
		super(null, null, 0, NullFolderDomainObject.class);
		throw new RuntimeException("Object may not be instantiated");
	}

	@Override
	public boolean isChangeable() {
		return false;
	}

	@Override
	public String getDescription() {
		return "Dummy FolderLink Domain Object";
	}
}

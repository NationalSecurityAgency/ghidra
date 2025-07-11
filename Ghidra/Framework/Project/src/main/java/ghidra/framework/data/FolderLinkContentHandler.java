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
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.Icon;

import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.util.Msg;

/**
 * {@code FolderLinkContentHandler} provide folder-link support.  
 * Implementation relies on {@link AppInfo#getActiveProject()} to provide life-cycle 
 * management for related transient-projects opened while following folder-links. 
 */
public class FolderLinkContentHandler extends LinkHandler<NullFolderDomainObject> {

	public static FolderLinkContentHandler INSTANCE = new FolderLinkContentHandler();

	public static final String FOLDER_LINK_CONTENT_TYPE = "FolderLink";

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
	 * Get linked domain folder.  
	 * <P>
	 * IMPORTANT: The use of external GhidraURL-based links is only supported in the context
	 * of a an active project which is used to manage the associated project view.
	 * <P>
	 * If the link refers to a folder within the active project (i.e., path based), the resulting 
	 * linked folder will be treated as part of that project, otherwise content will be treated
	 * as read-only.
	 *  
	 * @param folderLinkFile folder-link file.
	 * @return {@link LinkedGhidraFolder} referenced by specified folder-link file or null if 
	 * folderLinkFile content type is not {@value #FOLDER_LINK_CONTENT_TYPE}.
	 * @throws IOException if an IO or folder item access error occurs or a linkage error
	 * exists.
	 */
	public static LinkedGhidraFolder getLinkedFolder(DomainFile folderLinkFile) throws IOException {

		LinkFileInfo linkInfo = folderLinkFile.getLinkInfo();
		if (linkInfo == null || !linkInfo.isFolderLink()) {
			return null;
		}

		AtomicReference<LinkStatus> linkStatus = new AtomicReference<>();
		AtomicReference<String> errMsg = new AtomicReference<>();

		// Following internal linkage will catch circular internal linkage
		DomainFile folderLink = LinkHandler.followInternalLinkage(folderLinkFile,
			s -> linkStatus.set(s), err -> errMsg.set(err));

		LinkStatus s = linkStatus.get();
		if (s == LinkStatus.BROKEN) {
			String msg = errMsg.get();
			if (msg == null) {
				msg = "Unable to follow broken link";
			}
			// TODO: Should we just log warning instead?
			throw new IOException(msg + ": " + folderLink);
		}

		if (s == LinkStatus.EXTERNAL) {
			Project activeProject = AppInfo.getActiveProject();
			if (activeProject == null) {
				Msg.error(FolderLinkContentHandler.class,
					"Use of Linked Folders requires an active project.");
				return null;
			}
			return new LinkedGhidraFolder(folderLink, getLinkURL(folderLink));
		}

		if (folderLink != null) {

			ProjectData projectData;
			DomainFolder parent = folderLink.getParent();
			if (parent instanceof LinkedDomainFolder lf) {
				try {
					projectData = lf.getLinkedProjectData();
				}
				catch (IOException e) {
					throw new RuntimeException("Unexpected", e);
				}
			}
			else {
				projectData = parent.getProjectData();
			}

			String linkPath = LinkHandler.getAbsoluteLinkPath(folderLink);

			DomainFolder linkedFolder = projectData.getFolder(linkPath);
			if (linkedFolder != null) {
				return new LinkedGhidraFolder(folderLinkFile, linkedFolder);
			}
		}

		// TODO: Not sure if this can ever occur
		throw new FileNotFoundException("Invalid folder-link: " + folderLinkFile);
	}

}

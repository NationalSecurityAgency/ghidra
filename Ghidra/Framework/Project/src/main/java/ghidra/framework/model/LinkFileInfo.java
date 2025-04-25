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

import java.io.IOException;
import java.util.function.Consumer;

import ghidra.framework.data.*;
import ghidra.framework.data.LinkHandler.LinkStatus;
import ghidra.framework.protocol.ghidra.GhidraURL;

/**
 * {@link LinkFileInfo} provides access to link details for a {@link DomainFile} which is
 * a link-file.
 */
public interface LinkFileInfo {

	/**
	 * {@return the file that is associated with this link information.}
	 */
	public DomainFile getFile();

	/**
	 * Determine if the link "directly" refers to an external resource 
	 * (i.e., URL-based {@link #getLinkPath() link path}).
	 * <P>
	 * NOTE: It is important to understand that if this method returns {@code false} it
	 * may link to another link that is external.  If the a file external status is required
	 * an {@link LinkStatus#EXTERNAL} status should be checked using {@link #getLinkStatus(Consumer)}.
	 * 
	 * @return true if link-path is URL-based, else false
	 */
	public default boolean isExternalLink() {
		return GhidraURL.isGhidraURL(getLinkPath());
	}

	/**
	 * {@return true if this file is a folder-link, else false.}
	 */
	public default boolean isFolderLink() {
		return FolderLinkContentHandler.FOLDER_LINK_CONTENT_TYPE.equals(getFile().getContentType());
	}

	/**
	 * If this is a folder-link file get the corresponding linked folder.  Invoking this
	 * method on an {@link #isExternalLink() external-link} will cause the associated 
	 * project or repository to be opened and associated with the active project as a
	 * a viewed-project.  The resulting folder instance will return true to the method
	 * {@link DomainFolder#isLinked()}.  This method will recurse all internal folder-links
	 * which may be chained together.
	 * 
	 * @return a linked domain folder or null if not a valid folder-link.
	 */
	public LinkedGhidraFolder getLinkedFolder();

	/**
	 * Get the stored link-path.  This may be either be an absolute or relative path within the 
	 * link-file's project or a Ghidra URL.
	 * <P>
	 * If you want to ensure that a project path returned is absolute and normalized, then
	 * {@link #getAbsoluteLinkPath()} may be used.
	 * 
	 * @return associated link path
	 */
	public String getLinkPath();

	/**
	 * Get the stored link-path as a Ghidra URL or absolute normalized link-path from a link file.
	 * Path normalization eliminates any path element of "./" or "../".
	 * A local folder-link path will always end with a "/" path separator.
	 * Path normalization is not performed on Ghidra URLs.
	 * 
	 * @return Ghidra URL or absolute normalized link-path from a link file
	 * @throws IOException if linkFile has an invalid relative link-path that failed to normalize
	 */
	public String getAbsoluteLinkPath() throws IOException;

	/**
	 * Determine the link status.  If a status is {@link LinkStatus#BROKEN} and an 
	 * {@code errorConsumer} has been specified the error details will be reported.
	 * 
	 * @param errorConsumer broken link error consumer (may be null)
	 * @return link status
	 */
	public default LinkStatus getLinkStatus(Consumer<String> errorConsumer) {
		return LinkHandler.getLinkFileStatus(getFile(), errorConsumer);
	}

}

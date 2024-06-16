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

import javax.swing.Icon;

import ghidra.framework.data.FolderLinkContentHandler;

/**
 * {@code LinkedDomainFolder} extends {@link DomainFolder} for all folders which are 
 * accessable via a folder-link (see {@link FolderLinkContentHandler}).
 */
public interface LinkedDomainFolder extends DomainFolder {

	/**
	 * Get the real domain folder which corresponds to this linked-folder.
	 * @return domain folder
	 * @throws IOException if an IO error occurs
	 */
	public DomainFolder getLinkedFolder() throws IOException;

	/**
	 * Get the appropriate icon for this folder
	 * @param isOpen true if open icon, false for closed
	 * @return folder icon
	 */
	public Icon getIcon(boolean isOpen);

}

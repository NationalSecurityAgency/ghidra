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

import java.io.FileNotFoundException;
import java.io.IOException;

import javax.swing.Icon;

import ghidra.framework.data.FolderLinkContentHandler;

/**
 * {@code LinkedDomainFolder} extends {@link DomainFolder} for all folders which are 
 * accessable via a folder-link (see {@link FolderLinkContentHandler}).
 */
public interface LinkedDomainFolder extends DomainFolder {

	/**
	 * Get the project data that corresponds to the linked-project and contains the 
	 * {@link #getLinkedPathname()} which corresponds to this folder.
	 * 
	 * @return linked project data
	 * @throws IOException if an IO error occurs
	 */
	public ProjectData getLinkedProjectData() throws IOException;

	/**
	 * Get the project folder/file pathname for this this linked-folder relative to the 
	 * linked-folder root.
	 * 
	 * @return project pathname
	 */
	public String getLinkedPathname();

	/**
	 * Get the real domain folder which corresponds to this linked-folder.
	 * In the process of resolving the real folder a remote project or repository may be
	 * required.
	 * 
	 * @return domain folder
	 * @throws FileNotFoundException if folder does not exist (could occur due to connection issue)
	 * @throws IOException if an IO error occurs while connecting/accessing the associated
	 * project or repository.
	 */
	public DomainFolder getRealFolder() throws IOException;

	/**
	 * Get the appropriate icon for this folder
	 * 
	 * @param isOpen true if open icon, false for closed
	 * @return folder icon
	 */
	public Icon getIcon(boolean isOpen);

	/**
	 * Determine if this folder resides within an external project or repository.  The
	 * term "external" means the actual folder does not reside within the same project
	 * as the folder-link that referenced it and which was used to produce this
	 * linked folder instance.
	 * 
	 * @return true if linked-folder is external to the link file which was used to access,
	 * else false if internal to the same project.
	 */
	public boolean isExternal();

}

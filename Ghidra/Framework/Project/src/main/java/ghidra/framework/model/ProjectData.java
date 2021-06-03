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

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.remote.User;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.net.URL;
import java.util.List;

/**
 * The ProjectData interface provides access to all the data files and folders
 * in a project.
 */
public interface ProjectData {

	/**
	 * @return local storage implementation class
	 */
	public Class<? extends LocalFileSystem> getLocalStorageClass();

	/**
	 * Returns the root folder of the project.
	 */
	public DomainFolder getRootFolder();

	/**
	 * Get domain folder specified by an absolute data path.
	 * @param path the absolute path of domain folder relative to the data folder.
	 * @return domain folder or null if folder not found
	 */
	public DomainFolder getFolder(String path);

	/**
	 * Get the approximate number of files contained within the project.  The number 
	 * may be reduced if not connected to the shared repository.  Only the newer 
	 * indexed file-system supports this capability, a value of -1 will be
	 * returned for older projects utilizing the mangled file-system or if an
	 * IO Error occurs.
	 * An approximate number is provided since the two underlying file systems
	 * are consulted separately and the local private file-system does not
	 * distinguish between checked-out files and private files.  This number 
	 * is currently intended as a rough sizing number to disable certain features
	 * when very large projects are in use.  Generally the larger of the two
	 * file counts will be returned.
	 * @return number of project files or -1 if unknown.
	 */
	public int getFileCount();

	/**
	 * Get domain file specified by an absolute data path.
	 * @param path the absolute path of domain file relative to the root folder.
	 * @return domain file or null if file not found
	 */
	public DomainFile getFile(String path);

	/**
	 * Finds all open domain files and appends
	 * them to the specified list.
	 * @param list the list to receive the open domain files
	 */
	public void findOpenFiles(List<DomainFile> list);

	/**
	 * Get domain file specified by its unique fileID. 
	 * @param fileID domain file ID
	 * @return domain file or null if file not found
	 */
	public DomainFile getFileByID(String fileID);

	/**
	 * Get a URL for a shared domain file which is available 
	 * within a remote repository.
	 * @param path the absolute path of domain file relative to the root folder.
	 * @return URL object for accessing shared file from outside of a project, or
	 * null if file does not exist or is not shared.
	 */
	public URL getSharedFileURL(String path);

	/**
	 * Transform the specified name into an acceptable folder or file item name.  Only an individual folder
	 * or file name should be specified, since any separators will be stripped-out.
	 * NOTE: Uniqueness of name within the intended target folder is not considered.
	 * @param name
	 * @return valid name or "unknown" if no valid characters exist within name provided
	 */
	public String makeValidName(String name);

	/**
	 * Returns the projectLocator for the this ProjectData.
	 */
	public ProjectLocator getProjectLocator();

	/**
	 * Adds a listener that will be notified when any folder or file
	 * changes in the project.
	 * @param listener the listener to be notified of folder and file changes.
	 */
	public void addDomainFolderChangeListener(DomainFolderChangeListener listener);

	/**
	 * Removes the listener to be notified of folder and file changes.
	 * @param listener the listener to be removed.
	 */
	public void removeDomainFolderChangeListener(DomainFolderChangeListener listener);

	/**
	 * Sync the Domain folder/file structure with the underlying file structure.
	 * @param force if true all folders will be be visited and refreshed, if false
	 * only those folders previously visited will be refreshed.
	 */
	public void refresh(boolean force) throws IOException;

	/**
	 * Returns User object associated with remote repository or null if a remote repository
	 * is not used.
	 */
	public User getUser();

	/**
	 * Return the repository for this project data.
	 * @return null if the project is not associated with a repository
	 */
	public RepositoryAdapter getRepository();

	/**
	 * Convert a local project to a shared project. NOTE: The project should be closed and
	 * then reopened after this method is called.
	 * @param repository the repository that the project will be associated with.
	 * @param monitor task monitor 
	 * @throws IOException thrown if files under version control are still checked out, or
	 * if there was a problem accessing the filesystem
	 * @throws CancelledException if the conversion was cancelled while versioned files were being
	 * converted to private files. 
	 * 
	 */
	public void convertProjectToShared(RepositoryAdapter repository, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Update the repository for this project; the server may have changed or a different 
	 * repository is being used.  NOTE: The project should be closed and then reopened after this
	 * method is called.
	 * @param repository new repository to use
	 * @param monitor task monitor 
	 * @throws IOException thrown if files are still checked out, or if there was a problem accessing
	 * the filesystem
	 * @throws CancelledException if the user canceled the update
	 */
	public void updateRepositoryInfo(RepositoryAdapter repository, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Close the project storage associated with this project data object.
	 * NOTE: This should not be invoked if this object is utilized by a Project instance.
	 */
	public void close();

	/**
	 * @return the maximum name length permitted for folders or items.
	 */
	public int getMaxNameLength();

	/**
	 * Validate a folder/item name or path.
	 * @param name folder or item name
	 * @param isPath if true name represents full path
	 * @throws InvalidNameException if name is invalid
	 */
	public void testValidName(String name, boolean isPath) throws InvalidNameException;

}

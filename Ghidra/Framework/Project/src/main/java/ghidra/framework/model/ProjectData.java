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
import java.net.URL;
import java.util.Iterator;
import java.util.List;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.remote.User;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The ProjectData interface provides access to all the data files and folders
 * in a project.
 * <P>
 * NOTE: Iterating over this project data instance will ignore all link-files.  If links should
 * be handled please instantiate {@link ProjectDataUtils#descendantFiles(DomainFolder, DomainFileFilter)} 
 * with a suitable {@link DomainFileFilter}.
 */
public interface ProjectData extends Iterable<DomainFile> {

	/**
	 * @return local storage implementation class
	 */
	public Class<? extends LocalFileSystem> getLocalStorageClass();

	/**
	 * Returns the root folder of the project.
	 * @return root {@link DomainFolder} within project.
	 */
	public DomainFolder getRootFolder();

	/**
	 * Get domain folder specified by an absolute data path.  All internal folder-links will be followed.
	 * All path elements must refer to a valid internal non-conflicting folder or folder-link.  
	 * Internal folder-links will be resolved to their corresponding linked-folder.
	 * <P>
	 * External links are not followed.  If external links should be followed the 
	 * {@link #getFolder(String, DomainFolderFilter)} method should be used with an appropriate filter.
	 * <P>
	 * NOTE: Absolute paths do not include the project name which may be shown in the project 
	 * data tree in place of the root folder node {@code "/"}.
	 * 
	 * @param path the absolute path of a domain folder within the project.
	 * @return domain folder or null if folder not found
	 */
	public DomainFolder getFolder(String path);

	/**
	 * Get domain folder specified by an absolute data path.  If path refers to a 
	 * non-conflicting folder-link the specified filter will determine if it should be 
	 * followed to the linked-folder.  All folder path elements must satisfy the filter restrictions.
	 * <P>
	 * NOTE: Absolute paths do not include the project name which may be shown in the project 
	 * data tree in place of the root folder node {@code "/"}.
	 * 
	 * @param path the absolute path of a domain folder within the project.
	 * @param filter domain folder filter which constrains returned folder and following of 
	 * folder-links.
	 * @return domain folder or null if folder not found
	 */
	public DomainFolder getFolder(String path, DomainFolderFilter filter);

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
	 * Get domain file specified by an absolute data path. All internal folder-links will be followed.
	 * The returned file may be a link-file and {@link DomainFile#getLinkInfo()} result and/or
	 * {@link DomainFile#getDomainObjectClass()} / {@link DomainFile#getContentType()} should be 
	 * checked if needed. 
	 * <P>
	 * External links are not followed.  If external links should be followed the 
	 * {@link #getFile(String, DomainFileFilter)} method should be used with an appropriate filter.
	 * <P>
	 * NOTE: Absolute path does not include the project name which may be shown in the project 
	 * data tree in place of the root folder node {@code "/"}.
	 * 
	 * @param path the absolute path of domain file within the project.
	 * @return domain file or null if file not found
	 */
	public DomainFile getFile(String path);

	/**
	 * Get domain file specified by an absolute data path which satisfies the specified filter.
	 * If permitted by the filter the returned file may be a link-file.  This may occur if filter
	 * constrains based upon {@link DomainFile#getDomainObjectClass()} instead of 
	 * {@link DomainFile#getContentType()}.  {@link DomainFile#getLinkInfo()} result can be checked
	 * if needed. 
	 * <P>
	 * NOTE: Absolute path does not include the project name which may be shown in the project 
	 * data tree in place of the root folder node {@code "/"}.
	 * 
	 * @param path the absolute path of domain file within the project.
	 * @param filter domain file filter which constrains returned file and following of folder-links
	 * and file-links.
	 * @return domain file or null if file not found
	 */
	public DomainFile getFile(String path, DomainFileFilter filter);

	/**
	 * Finds all open domain files and appends them to the specified list.
	 * @param list the list to receive the open domain files
	 */
	public void findOpenFiles(List<DomainFile> list);

	/**
	 * Find all project files which are currently checked-out to this project
	 * @param monitor task monitor (no progress updates)
	 * @return list of current checkout files
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task cancelled
	 */
	public List<DomainFile> findCheckedOutFiles(TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Determine if any domain files listed do not correspond to a checkout in the specified 
	 * newRespository prior to invoking {@link #updateRepositoryInfo(RepositoryAdapter, boolean, TaskMonitor)}.
	 * @param checkoutList project domain files to check
	 * @param newRepository repository to check against before updating
	 * @param monitor task monitor
	 * @return true if one or more files are not valid checkouts in newRepository
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task cancelled
	 */
	public boolean hasInvalidCheckouts(List<DomainFile> checkoutList,
			RepositoryAdapter newRepository, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Get domain file specified by its unique fileID. Link following is not performed.
	 * @param fileID domain file ID
	 * @return domain file or null if file not found
	 */
	public DomainFile getFileByID(String fileID);

	/**
	 * Transform the specified name into an acceptable folder or file item name.  Only an individual folder
	 * or file name should be specified, since any separators will be stripped-out.
	 * NOTE: Uniqueness of name within the intended target folder is not considered.
	 * @param name original name to be sanitized
	 * @return valid name or "unknown" if no valid characters exist within name provided
	 */
	public String makeValidName(String name);

	/**
	 * Returns the projectLocator for the this ProjectData.
	 * @return project locator object
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
	 * @param force if true all folders will be visited and refreshed, if false
	 * only those folders previously visited will be refreshed.
	 */
	public void refresh(boolean force);

	/**
	 * Returns User object associated with remote repository or null if a remote repository
	 * is not used.
	 * @return current remote user identity or null
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
	 * repository is being used.  Any existing checkout which is not recognized/valid by 
	 * newRepository will be terminated and a local .keep file created.  
	 * NOTE: The project should be closed and then reopened after this method is called.
	 * @param newRepository new repository to use
	 * @param force if true any existing local checkout which is not recognized/valid
	 *    for newRepository will be forceably terminated if offline with old repository. 
	 * @param monitor task monitor 
	 * @throws IOException thrown if files are still checked out, or if there was a problem accessing
	 * the filesystem
	 * @throws CancelledException if the user canceled the update
	 */
	public void updateRepositoryInfo(RepositoryAdapter newRepository, boolean force,
			TaskMonitor monitor) throws IOException, CancelledException;

	/**
	 * Initiate disposal of this project data object.  Any files already open will delay 
	 * disposal until they are closed.
	 * NOTE: This should only be invoked by the controlling object which created/opened this
	 * instance to avoid premature disposal. 
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

	/**
	 * Generate a repository URL which corresponds to this project data if applicable.
	 * Local private projects will return null;
	 * @return repository URL which corresponds to this project data or null if not applicable.
	 */
	public URL getSharedProjectURL();

	/**
	 * Generate a local URL which corresponds to this project data if applicable.
	 * Remote transient project data will return null;
	 * @return local URL which corresponds to this project data or null if not applicable.
	 */
	public URL getLocalProjectURL();

	/**
	 * Return a {@link DomainFile} iterator over all non-link files within this project data store.
	 * If links should be followed use an appropropriate static method from {@link ProjectDataUtils}.
	 * @return domain file iterator
	 */
	@Override
	public default Iterator<DomainFile> iterator() {
		return ProjectDataUtils.descendantFiles(getRootFolder()).iterator();
	}
}

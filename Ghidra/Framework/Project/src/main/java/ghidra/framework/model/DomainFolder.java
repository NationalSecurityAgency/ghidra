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

import java.io.File;
import java.io.IOException;

import ghidra.framework.store.FolderNotEmptyException;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>DomainFolder</code> provides a storage interface for project folders.  A 
 * <code>DomainFolder</code> is an immutable reference to a folder contained within a project.  The 
 * state of a <code>DomainFolder</code> object does not track name/parent changes made to the 
 * referenced project folder.
 */
public interface DomainFolder extends Comparable<DomainFolder> {
	/**
	 * Character used to separate folder and item names within a path string.
	 */
	public static final String SEPARATOR = "/";

	/**
	 * Name extension to add when attempting to avoid a duplicate name.
	 */
	public static final String COPY_SUFFIX = ".copy";

	/**
	 * Return this folder's name.
	 * @return the name
	 */
	public String getName();

	/**
	 * Set the name on this domain folder.
	 * @param newName domain folder name
	 * @return renamed domain file (the original DomainFolder object becomes invalid since it is 
	 * immutable)
	 * @throws InvalidNameException if newName contains illegal characters
	 * @throws DuplicateFileException if a folder named newName 
	 * already exists in this files domain folder.
	 * @throws FileInUseException if any file within this folder or its descendants is 
	 * in-use / checked-out.
	 * @throws IOException thrown if an IO or access error occurs.
	 */
	public DomainFolder setName(String newName) throws InvalidNameException, IOException;

	/**
	 * Returns the local storage location for the project that this DomainFolder belongs to.
	 * @return the locator
	 */
	public ProjectLocator getProjectLocator();

	/**
	 * Returns the project data
	 * @return the project data
	 */
	public ProjectData getProjectData();

	/**
	 * Returns the path name to the domain object.
	 * @return the path name
	 */
	public String getPathname();

	/**
	 * Returns true if this file is in a writable project.
	 * @return true if writable
	 */
	public boolean isInWritableProject();

	/**
	 * Return parent folder or null if this DomainFolder is the root folder.
	 * @return the parent
	 */
	public DomainFolder getParent();

	/**
	 * Get DomainFolders in this folder.
	 * This returns cached information and does not force a full refresh.
	 * @return list of sub-folders
	 */
	public DomainFolder[] getFolders();

	/**
	 * Return the folder for the given name.
	 * @param name of folder to retrieve
	 * @return folder or null if there is no folder by the given name.
	 */
	public DomainFolder getFolder(String name);

	/**
	 * Get the domain file in this folder with the given name.
	 * @param name name of file in this folder to retrieve
	 * @return domain file or null if there is no domain file in this folder with the given name.
	 */
	public DomainFile getFile(String name);

	/**
	 * Determine if this folder contains any sub-folders or domain files.
	 * @return true if this folder is empty.
	 */
	public boolean isEmpty();

	/**
	 * Get all domain files in this folder.
	 * This returns cached information and does not force a full refresh.
	 * @return list of domain files
	 */
	public DomainFile[] getFiles();

	/**
	 * Add a domain object to this folder.
	 * @param name domain file name
	 * @param obj domain object to be stored
	 * @param monitor progress monitor
	 * @return domain file created as a result of adding
	 * the domain object to this folder
	 * @throws DuplicateFileException thrown if the file name already exists
	 * @throws InvalidNameException if name is an empty string
	 * or if it contains characters other than alphanumerics.
	 * @throws IOException if IO or access error occurs
	 * @throws CancelledException if the user cancels the create.
	 */
	public DomainFile createFile(String name, DomainObject obj, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException;

	/**
	 * Add a new domain file to this folder.
	 * @param name domain file name
	 * @param packFile packed file containing domain file data
	 * @param monitor progress monitor
	 * @return domain file created as a result of adding
	 * the domain object to this folder
	 * @throws DuplicateFileException thrown if the file name already exists
	 * @throws InvalidNameException if name is an empty string
	 * or if it contains characters other than alphanumerics.
	 * @throws IOException if IO or access error occurs
	 * @throws CancelledException if the user cancels the create.
	 */
	public DomainFile createFile(String name, File packFile, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException;

	/**
	 * Create a subfolder of this folder.
	 * @param folderName sub-folder name
	 * @return the folder
	 * @throws DuplicateFileException if a folder by
	 * this name already exists
	 * @throws InvalidNameException if name is an empty string of if it contains characters other 
	 * than alphanumerics.
	 * @throws IOException if IO or access error occurs
	 */
	public DomainFolder createFolder(String folderName) throws InvalidNameException, IOException;

	/**
	 * Deletes this folder and all of its contents
	 * @throws IOException if IO or access error occurs
	 * @throws FolderNotEmptyException Thrown if the subfolder is not empty.
	 */
	public void delete() throws IOException;

	/**
	 * Move this folder into the newParent folder.  If connected to an archive
	 * this affects both private and repository folders and files.  If not
	 * connected, only private folders and files are affected.
	 * @param newParent new parent folder within the same project
	 * @return the newly relocated folder (the original DomainFolder object becomes invalid since 
	 * it is immutable)
	 * @throws DuplicateFileException if a folder with the same name 
	 * already exists in newParent folder.
	 * @throws FileInUseException if this folder or one of its descendants 
	 * contains a file which is in-use / checked-out.
	 * @throws IOException thrown if an IO or access error occurs.
	 */
	public DomainFolder moveTo(DomainFolder newParent) throws IOException;

	/**
	 * Copy this folder into the newParent folder.
	 * @param newParent new parent folder
	 * @param monitor the task monitor
	 * @return the copied folder
	 * @throws DuplicateFileException if a folder or file by
	 * this name already exists in the newParent folder
	 * @throws IOException thrown if an IO or access error occurs.
	 * @throws CancelledException if task monitor cancelled operation.
	 */
	public DomainFolder copyTo(DomainFolder newParent, TaskMonitor monitor) throws IOException,
			CancelledException;

	/**
	 * Allows the framework to react to a request to make this folder the "active" one.
	 */
	public void setActive();
}

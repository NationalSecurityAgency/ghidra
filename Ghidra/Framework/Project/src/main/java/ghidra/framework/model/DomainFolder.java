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
import java.net.URL;

import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.framework.data.LinkHandler;
import ghidra.framework.store.FolderNotEmptyException;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * {@link DomainFolder} provides a storage interface for a project folder.  A 
 * domain folder is an immutable reference to a folder contained within a project.  Provided the
 * corresponding path exists within the project it may continue to be used to create and access
 * its files and sub-folders.  The state of a folder object does not track name/parent changes made 
 * to the referenced project file.  An up-to-date instance may be obtained from 
 * {@link ProjectData#getFolder(String)} or may be returned by any method used to move or rename it.  
 * The project data object for the active {@link Project}  may be obtained via 
 * {@link Project#getProjectData()}.
 * <P>
 * <B><U>Link Files</U></B>
 * <P>
 * Link files may exist or be created within a folder.  See {@link DomainFile} for more information.
 * <P>
 * Obtaining the folder which corresponds to a linked-folder is done indirectly via a link file.
 * There are different ways to arrive on a linked-folder:
 * <ol>
 * <li>Obtained directly via a folder request by path, or</li>
 * <li>discovered by the presence of a link file which corresponds to a linked-folder.</li>
 * </ol>
 * <P>
 * Example #1, where folder path is known (external links will be followed):
 * <pre>
 *    DomainFolder folder = projectData.getFolder("/A/B/linkedFolder");
 *    if (folder != null) {
 *       if (folder.isLinked())
 *          LinkedDomainFolder linkedFolder = (LinkedDomainFolder) folder;
 *          // linkedFolder behaves the same as a normal folder
 *       }
 *       DomainFile[] files = folder.getFiles();
 *    }
 * </pre>
 * <P>
 * Example #2, where we locate via a link file:
 * <pre>{@code
 *    DomainFile file = ...
 *    LinkFileInfo linkInfo = file.getLinkInfo();
 *    if (linkInfo != null && linkInfo.isFolderLink()) {
 *       LinkStatus status = linkInfo.getLinkStatus(null);
 *       if (status != LinkStatus.INTERNAL) {
 *          return; // Only consider internally linked-folder, skip broken or external link
 *       }
 *       LinkedDomainFolder linkedFolder = linkInfo.getLinkedFolder();
 *       if (linkedFolder != null) {    
 *          DomainFile[] files = linkedFolder.getFiles();
 *       }
 *    }
 * }</pre>
 * <P>
 * The utility method {@link ProjectDataUtils#descendantFiles(DomainFolder, DomainFileFilter)}
 * may also come in handy to iterate over folder contents while restricting treatment of
 * linked content.
 */
public interface DomainFolder extends Comparable<DomainFolder> {

	// TODO: Need more robust folder icon support to allow repository connection state
	// for root node to be reflected in icon (GP-5333)

	public static final Icon OPEN_FOLDER_ICON = new GIcon("icon.datatree.node.domain.folder.open");

	public static final Icon CLOSED_FOLDER_ICON =
		new GIcon("icon.datatree.node.domain.folder.closed");

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
	 * Returns the full path name to this folder
	 * @return the path name
	 */
	public String getPathname();

	/**
	 * Returns true if the given folder is the same as this folder based on path
	 * and underlying project/repository.  Unlike the {@link Object#equals(Object)} check, this 
	 * method handles cases where the folder provided may correspond to another project instance 
	 * which is considered the same as the project that this folder is contained within.
	 * 
	 * @param folder the potential same or descendant folder to check
	 * @return true if the given folder is the same or a child of this folder or 
	 * one of its descendants.
	 */
	public boolean isSame(DomainFolder folder);

	/**
	 * Returns true if the given folder is the same or a child of this folder or 
	 * one of its descendants based on path and underlying project/repository.  Unlike the 
	 * {@link Object#equals(Object)} check, this method
	 * handles cases where the folder provided may correspond to another project instance 
	 * which is considered the same as the project that this folder is contained within.
	 * 
	 * @param folder the potential same or descendant folder to check
	 * @return true if the given folder is the same or a child of this folder or 
	 * one of its descendants.
	 */
	public boolean isSameOrAncestor(DomainFolder folder);

	/**
	 * Get a remote Ghidra URL for this domain folder if available within an associated shared
	 * project repository.  URL path will end with "/".  A null value will be returned if shared 
	 * folder does not exist and may also be returned if shared repository is not connected or a 
	 * connection error occurs.
	 * @return remote Ghidra URL for this folder or null
	 */
	public URL getSharedProjectURL();

	/**
	 * Get a local Ghidra URL for this domain file if available within the associated non-transient
	 * local project.  A null value will be returned if project is transient.
	 * @return local Ghidra URL for this folder or null if transient or not applicable
	 */
	public URL getLocalProjectURL();

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
	 * This may return cached information and does not force a full refresh.
	 * @return list of sub-folders
	 */
	public DomainFolder[] getFolders();

	/**
	 * Return the folder for the given name.
	 * Folder link-files are ignored.
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
	 * This may return cached information and does not force a full refresh.
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
	 * Create a link-file within this folder which references the specified file or folder 
	 * {@code pathname} within the project specified by {@code sourceProjectData}.  The link-file 
	 * may correspond to various types of content (e.g., Program, Trace, Folder, etc.) based upon 
	 * the specified {@link LinkHandler} instance.
	 * 
	 * @param sourceProjectData referenced content project data within which specified path exists.
	 * If this differ's from this folder's project a Ghidra URL will be used, otherwise and internal
	 * link path reference will be used.
	 * @param pathname an absolute path of project folder or file within the specified source 
	 * project data (a Ghidra URL is not permitted)
	 * @param makeRelative if true, and this file is contained within the same active 
	 * {@link ProjectData} instance as {@code newParent}, an internal-project relative path 
	 * link-file will be created.
	 * @param linkFilename name of link-file to be created within this folder.  NOTE: This name may 
	 * be modified to ensure uniqueness within this folder.
	 * @param lh link-file handler used to create specific link-file (see derived implementations
	 * of {@link LinkHandler} and their public static INSTANCE.
	 * @return newly created link-file 
	 * @throws IOException if IO error occurs during link creation
	 */
	public DomainFile createLinkFile(ProjectData sourceProjectData, String pathname,
			boolean makeRelative, String linkFilename, LinkHandler<?> lh) throws IOException;

	/**
	 * Create an external link-file within this folder which references the specified 
	 * {@code ghidraUrl} and whose content is defined by the specified {@link LinkHandler lh} 
	 * instance.
	 * 
	 * @param ghidraUrl a Ghidra URL which corresponds to a file or a folder based on the designated
	 * {@link LinkHandler lh} instance.  Only rudimentary URL checks are performed.
	 * @param linkFilename name of link-file to be created within this folder.  NOTE: This name may 
	 * be modified to ensure uniqueness within this folder.
	 * @param lh link-file handler used to create specific link-file (see derived implementations
	 * of {@link LinkHandler} and their public static INSTANCE.
	 * @return newly created link-file 
	 * @throws IOException if IO error occurs during link creation
	 */
	public DomainFile createLinkFile(String ghidraUrl, String linkFilename, LinkHandler<?> lh)
			throws IOException;

	/**
	 * Create a subfolder within this folder.
	 * @param folderName sub-folder name
	 * @return the new folder
	 * @throws DuplicateFileException if a folder by this name already exists
	 * @throws InvalidNameException if name is an empty string of if it contains characters other 
	 * than alphanumerics.
	 * @throws IOException if IO or access error occurs
	 */
	public DomainFolder createFolder(String folderName) throws InvalidNameException, IOException;

	/**
	 * Deletes this folder, if empty, from the local filesystem
	 * @throws IOException if IO or access error occurs
	 * @throws FolderNotEmptyException Thrown if this folder is not empty.
	 */
	public void delete() throws IOException;

	/**
	 * Move this folder into the newParent folder.  If connected to a repository
	 * this moves both private and repository folders/files.  If not
	 * connected, only private folders/files are moved.
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
	 * @return the new copied folder
	 * @throws DuplicateFileException if a folder or file by
	 * this name already exists in the newParent folder
	 * @throws IOException thrown if an IO or access error occurs.
	 * @throws CancelledException if task monitor cancelled operation.
	 */
	public DomainFolder copyTo(DomainFolder newParent, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Copy this folder into the newParent folder as a folder-link.  A folder-link references another
	 * folder without actually copying all of its children.  If this folder is associated with a 
	 * temporary transient project (i.e., not a locally managed project) the generated link will 
	 * refer to the this folder with a Ghidra URL.  If this folder is contained within the 
	 * same active {@link ProjectData} instance as {@code newParent} an internal link reference 
	 * will be made.
	 * 
	 * @param newParent new parent folder where link-file is to be created
	 * @param relative if true, and this folder is contained within the same active 
	 * {@link ProjectData} instance as {@code newParent}, an internal-project relative path 
	 * folder-link will be created.
	 * @return newly created domain file which is a folder-link (i.e., link-file).
	 * @throws IOException if an IO or access error occurs.
	 */
	public DomainFile copyToAsLink(DomainFolder newParent, boolean relative) throws IOException;

	/**
	 * Allows the framework to react to a request to make this folder the "active" one.
	 */
	public void setActive();

	/**
	 * Determine if this folder corresponds to a linked-folder which directly corresponds to a
	 * folder-link file.  While this method is useful for identify a linked-folder root, in some
	 * cases it may be preferrable to simply check for instanceof {@link LinkedDomainFolder} which 
	 * applies to the linked-folder root as well as its child sub-folders.
	 *   
	 * @return true if folder corresponds to a linked-folder, else false.
	 */
	public default boolean isLinked() {
		return false;
	}
}

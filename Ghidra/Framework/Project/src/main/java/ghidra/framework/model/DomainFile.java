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

import java.io.*;
import java.net.URL;
import java.util.List;
import java.util.Map;

import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.framework.client.NotConnectedException;
import ghidra.framework.data.*;
import ghidra.framework.store.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * {@link DomainFile} provides a storage interface for a project file.  A domain file
 * provides an immutable reference to a stored file contained within a project.  The state 
 * of a file object does not track name/parent changes made to the referenced project file.
 * An up-to-date object may be obtained from {@link ProjectData#getFile(String)}, 
 * {@link ProjectData#getFileByID(String)}, or may be returned by any method used to move or rename 
 * it.  The project data object for the active 
 * {@link Project} may be obtained via {@link Project#getProjectData()}.
 * <P>
 * <B><U>Link Files</U></B>
 * <P>
 * Link files may exist or be created within a project where the methods {@link #isLink()} and
 * {@link #getLinkInfo()} may be used to obtain more details about a link and in the case of a 
 * linked-folder can facilitate obtainining the referenced {@link LinkedGhidraFolder}.  This 
 * information object can also be used to determine if the referenced file or folder is external
 * to this file's project.
 * <P>
 * A link-file can become "broken" if its reference has one of the following conditions 
 * occur:
 * <ol>
 * <li>A referenced internal file or folder does not exist, or</li>
 * <li>the nature/content-type of the referenced file does not match the designated type when the
 * link was created, or</li>
 * <li>the link has a circular reference path within this file's project.</li>
 * </ol>
 * <P>
 * The method {@link LinkFileInfo#getLinkStatus(java.util.function.Consumer)} may be used to 
 * determine if a link is "broken".  Use of a broken link may result in an IOException or other
 * failure.  The domain object for a file-link (e.g., ProgramLink) may be obtained in the same 
 * manner as a normal file (e.g., {@link #getDomainObject(Object, boolean, boolean, TaskMonitor)}. 
 * However, as with any file it is recommended that {@link #getDomainObjectClass()} first be used 
 * to ensure the file corresponds to the expected/supported content type.
 * <P>
 * <B>NOTE:</B> Using external links to shared projects or 
 * repositories may result in required authentication; which in headless situations may be 
 * limited by the active authentication handler (see {@link LinkFileInfo#isExternalLink()} and
 * {@link LinkFileInfo#getLinkStatus(java.util.function.Consumer)} for more details).
 * <P>
 * Link files can facilitate a link to either a folder or another file of a specific content type 
 * within a Ghidra project.  Here's why someone might choose to use them:
 * <ul>
 * <li><B>File Organization:</B> links allow users to organize files and folders in a way that makes 
 * sense for their workflow without duplicating data. A single file can appear to exist in multiple 
 * locations without taking up additional space.</li>
 * <li><B>Dynamic Updates:</B> If the original file or folder is modified, the changes are automatically 
 * reflected wherever the link is used, ensuring consistency without manual updates.</li>
 * <li><B>Shared Resources:</B> links can be used to establish shortcuts to files stored in different 
 * repositories, projects or directories, enabling easy access without navigating deeply nested folder 
 * structures or replicating stored data.</li>
 * <li><B>System Configuration:</B> links can be used to link different versions of programs or libraries 
 * without changing paths.</li>
 * </ul>
 */
public interface DomainFile extends Comparable<DomainFile> {

	public static final Icon UNSUPPORTED_FILE_ICON = new GIcon("icon.domain.file.uknown");

	/**
	* Use with getDomainObject to request the default version.  The default version is
	* the private file or check-out file if one exists, or the latest version from the
	* version controlled file system. 
	*/
	public static final int DEFAULT_VERSION = FolderItem.LATEST_VERSION;

	/**
	 * Event property name for Read-only setting.
	 */
	public final static String READ_ONLY_PROPERTY = "READ_ONLY";

	/**
	 * Get the name of this project file
	 * @return the name
	 */
	public String getName();

	/**
	 * Check for existence of domain file.
	 * @return true if file exists.  A proxy domain file will always return false.
	 */
	public boolean exists();

	/**
	 * Returns a unique file-ID if one has been established or null.  Examples which may result in 
	 * null ID:
	 * <ul>
	 * <li>Very old project file which pre-dates introduction of file ID, or</li>
	 * <li>Remote versioned file with lost connection</li> 
	 * </ul>
	 * @return the file-ID or null if failed to obtain ID.
	 */
	public String getFileID();

	/**
	 * Set the name on this domain file.
	 * @param newName domain file name
	 * @return renamed domain file (the original DomainFile object becomes invalid since it is immutable) 
	 * @throws InvalidNameException if newName contains illegal characters
	 * @throws DuplicateFileException if a file named newName 
	 * already exists in this files domain folder.
	 * @throws FileInUseException if this file is in-use / checked-out.
	 * @throws IOException if an IO or access error occurs.
	 */
	public DomainFile setName(String newName) throws InvalidNameException, IOException;

	/**
	 * Returns the full path name to this file
	 * @return the path name
	 */
	public String getPathname();

	/**
	 * Get a remote Ghidra URL for this domain file if available within an associated shared
	 * project repository.  A null value will be returned if shared file does not exist and
	 * may also be returned if shared repository is not connected or a connection error occurs.
	 * @param ref reference within a file, may be null.  NOTE: such reference interpretation
	 * is specific to a domain object and tooling with limited support.
	 * @return remote Ghidra URL for this file or null
	 */
	public URL getSharedProjectURL(String ref);

	/**
	 * Get a local Ghidra URL for this domain file if available within the associated non-transient
	 * local project.  A null value will be returned if project is transient.
	 * @param ref reference within a file, may be null.  NOTE: such reference interpretation
	 * is specific to a domain object and tooling with limited support.
	 * @return local Ghidra URL for this file or null if transient or not applicable
	 */
	public URL getLocalProjectURL(String ref);

	/**
	 * Returns the local storage location for the project that this DomainFile belongs to.
	 * @return the location
	 */
	public ProjectLocator getProjectLocator();

	/**
	 * Returns content-type string for this file
	 * @return the file content type or a reserved content type {@link ContentHandler#MISSING_CONTENT}
	 * or {@link ContentHandler#UNKNOWN_CONTENT}.
	 */
	public String getContentType();

	/**
	 * Returns the underlying Class for the domain object in this domain file.
	 * @return the class or null if does not correspond to a domain object.
	 */
	public Class<? extends DomainObject> getDomainObjectClass();

	/**
	 * Get the parent domain folder for this domain file.
	 * @return the parent
	 */
	public DomainFolder getParent();

	/**
	 * Returns changes made to versioned file by others since checkout was performed.
	 * NOTE: This method is unable to cope with version issues which may require an
	 * upgrade.
	 * @return change set or null
	 * @throws VersionException latest version was created with a different version of software
	 * which prevents rapid determination of change set.
	 * @throws IOException if a folder item access error occurs or change set was 
	 * produced by newer version of software and can not be read
	 */
	public ChangeSet getChangesByOthersSinceCheckout() throws VersionException, IOException;

	/**
	 * Opens and returns the current domain object.  If the domain object is already opened,
	 * then the existing open domain object is returned.
	 * @param consumer consumer of the domain object which is responsible for
	 * releasing it after use. When all the consumers using the domain object release it, then
	 * the object is closed and its resources released.
	 * @param okToUpgrade if true, allows the system to upgrade out of data domain objects to
	 * be in compliance with the current version of Ghidra. A Version exception will be thrown
	 * if the domain object cannot be upgraded OR okToUpgrade is false and the domain object is
	 * out of date.
	 * @param okToRecover if true, allows the system to recover unsaved file changes which 
	 * resulted from a crash.  If false, any existing recovery data will be deleted.
	 * This flag is only relevant if project is open for update (isInProject) and the file can be
	 * opened for update.
	 * @param monitor permits monitoring of open progress.
	 * @return an open domain object can be modified and saved. (Not read-only)
	 * @throws VersionException if the domain object could not be read due
	 * to a version format change.  If okToUpgrade is true, then a VersionException indicates
	 * that the domain object cannot be upgraded to the current format.  If okToUpgrade is false,
	 * then the VersionException only means the object is not in the current format - it 
	 * may or may not be possible to upgrade. 
	 * @throws IOException if an IO or access error occurs.
	 * @throws CancelledException if monitor cancelled operation
	 */
	public DomainObject getDomainObject(Object consumer, boolean okToUpgrade, boolean okToRecover,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException;

	/**
	 * Returns the domainObject for this DomainFile only if it is already open.
	 * @param consumer the consumer that will use the object.
	 * @return the already opened domainObject or null if it is not currently open.
	 */
	public DomainObject getOpenedDomainObject(Object consumer);

	/**
	 * Returns a "read-only" version of the domain object.  "Read-only" means that the domain
	 * object cannot be saved back into its original domain object. It can still be modified
	 * and saved to a new domain file.  The domain object will be assigned a temporary domain
	 * file that will not allow a "save" operation. The user must do a "save as"
	 * to a new filename.
	 * @param consumer consumer of the domain object which is responsible for
	 * releasing it after use.
	 * @param version the domain object version requested.  DEFAULT_VERSION should be 
	 * specified to open the current version.  
	 * @param monitor permits monitoring of open progress.
	 * @return a new domain object that is disassociated from its original domain file.
	 * @throws VersionException if the domain object could not be read due
	 * to a version format change.
	 * @throws FileNotFoundException if the stored file/version was not found.
	 * @throws IOException if an IO or access error occurs.
	 * @throws CancelledException if monitor cancelled operation
	 */
	public DomainObject getReadOnlyDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException;

	/**
	 * Returns a new DomainObject that cannot be changed or saved to its original file.
	 * NOTE: The use of this method should generally be avoided since it can't
	 * handle version changes that may have occured and require a data upgrade
	 * (e.g., DB schema change).
	 * @param consumer consumer of the domain object which is responsible for
	 * releasing it after use.
	 * @param version the domain object version requested.  DEFAULT_VERSION should be 
	 * specified to open the current version.  
	 * @param monitor permits monitoring of open progress.
	 * @return a new domain object that is disassociated from its original domain file
	 * and cannot be modified
	 * @throws VersionException if the domain object could not be read due
	 * to a version format change.
	 * @throws FileNotFoundException if the stored file/version was not found.
	 * @throws IOException if an IO or access error occurs.
	 * @throws CancelledException if monitor cancelled operation
	 */
	public DomainObject getImmutableDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException;

	/**
	 * Save the <CODE>DomainObject</CODE> associated with this file.
	 * @param monitor monitor for the task that is doing the save on the file
	 * @throws FileInUseException if the file is open for update by someone else, or
	 * a transient-read is in progress.
	 * @throws IOException if an IO error occurs.
	 * @throws CancelledException if monitor cancelled operation
	 */
	public void save(TaskMonitor monitor) throws IOException, CancelledException;

	/**
	 * Return whether this domain object can be saved (i.e., updated/overwritten).
	 * @return true if the user is the owner AND the file is in
	 * the active project AND the file is not read-only.
	 */
	public boolean canSave();

	/**
	 * Prior to invoking getDomainObject, this method can be used to determine if
	 * unsaved changes can be recovered on the next open.
	 * @return true if recovery data exists.
	 */
	public boolean canRecover();

	/**
	 * If the file has an updatable domain object with unsaved changes, generate a recovery 
	 * snapshot.
	 * @return true if snapshot successful or not needed, false if file is busy which prevents 
	 * snapshot, or snapshot was cancelled.
	 * @throws IOException if there is an exception saving the snapshot
	 */
	public boolean takeRecoverySnapshot() throws IOException;

	/**
	 *  Returns true if this file is in a writable project.
	 * @return true if writable
	 */
	public boolean isInWritableProject();

	/**
	 * Get a long value representing the time when the data was last modified.
	 * @return the time
	 */
	public long getLastModifiedTime();

	/**
	 * Get the state based Icon image for the domain file based upon its content class.
	 * @param disabled true if the icon return should be rendered as 
	 * not enabled
	 * @return image icon
	 */
	public Icon getIcon(boolean disabled);

	/**
	 * Returns true if this is a checked-out file.
	 * @return true if checked-out
	 */
	public boolean isCheckedOut();

	/**
	 * Returns true if this a checked-out file with exclusive access.
	 * @return true if checked-out exclusively
	 */
	public boolean isCheckedOutExclusive();

	/**
	 * Returns true if this is a checked-out file which has been modified since it was checked-out.
	 * @return true if modified since check-out
	 */
	public boolean modifiedSinceCheckout();

	/**
	 * Returns true if this file may be checked-out from the associated repository.
	 * User's with read-only repository access will not have checkout ability.
	 * @return true if can checkout
	 */
	public boolean canCheckout();

	/**
	 * Returns true if this file may be checked-in to the associated repository.
	 * 
	 * Note: this does not take into consideration cases where the file is currently
	 * in-use which may cause a failure if a checkin is attempted.
	 * 
	 * @return true if a check-in can be attempted (i.e., file is checked-out with changes),
	 * else false
	 */
	public boolean canCheckin();

	/**
	 * Returns true if this file can be merged with the current versioned file.
	 * 
	 * Note: this does not take into consideration cases where the file is currently
	 * in-use which may cause a failure if a merge is attempted.
	 * 
	 * @return true if a merge can be attempted (i.e., file is checked-out and a newer 
	 * version exists), else false
	 */
	public boolean canMerge();

	/**
	 * Returns true if this private file may be added to the associated repository.
	 * 
	 * Note: this does not take into consideration cases where the file is currently
	 * in-use which may cause a failure if add to repository is attempted.
	 * 
	 * @return true if add to the repository can be attempted (i.e., file in active project
	 * is not versioned or hijacked)
	 */
	public boolean canAddToRepository();

	/**
	 * Sets the object to read-only.  This method may only be invoked
	 * for private files (i.e., not versioned).
	 * @param state if true file will be read-only and may not be updated, if false the 
	 * file may be updated.
	 * @throws IOException if an IO error occurs.
	 */
	public void setReadOnly(boolean state) throws IOException;

	/**
	 * Returns whether this file is explicitly marked as read-only.  This method is only supported
	 * by the local file system and does not apply to a versioned file that is not checked-out.
	 * A versioned file that is not checked-out will always return false, while a 
	 * {@link DomainFileProxy} will always return true.
	 * From a framework point of view a read-only file can never be changed.
	 * @return true if this file is marked read-only
	 */
	public boolean isReadOnly();

	/**
	 * Return true if this is a versioned database, else false
	 * @return true if versioned
	 */
	public boolean isVersioned();

	/**
	 * Returns true if the file is versioned but a private copy also exists.
	 * @return true if hijacked
	 */
	public boolean isHijacked();

	/**
	 * Return the latest version
	 * @return the version
	 */
	public int getLatestVersion();

	/**
	 * Returns true if this file represents the latest version of the associated domain object.
	 * @return true if the latest version
	 */
	public boolean isLatestVersion();

	/**
	 * Return either the latest version if the file is not checked-out or the version that
	 * was checked-out or a specific version that was requested.
	 * @return the version
	 */
	public int getVersion();

	/**
	 * Returns list of all available versions.
	 * @return the versions
	 * @throws IOException if there is an exception getting the history
	 */
	public Version[] getVersionHistory() throws IOException;

	/** 
	 * Adds this private file to version control.
	 * @param comment new version comment
	 * @param keepCheckedOut if true, the file will be initially checked-out.  This option will be
	 * ignored if file is currently open in which case file will remain checked-out.
	 * @param monitor progress monitor
	 * @throws FileInUseException if this file is in-use.
	 * @throws IOException if an IO or access error occurs.  Also if file is not 
	 * private.
	 * @throws CancelledException if the monitor cancelled the operation
	 */
	public void addToVersionControl(String comment, boolean keepCheckedOut, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Checkout this file for update.  If this file is already 
	 * private, this method does nothing.
	 * @param exclusive if true an exclusive checkout will be requested 
	 * @param monitor progress monitor
	 * @return true if checkout successful, false if an exclusive checkout was not possible
	 * due to other users having checkouts of this file.  A request for a non-exclusive checkout 
	 * will never return false.
	 * @throws IOException if an IO or access error occurs.
	 * @throws CancelledException if task monitor cancelled operation.
	 */
	public boolean checkout(boolean exclusive, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	* Performs check in to associated repository.  File must be checked-out 
	* and modified since checkout.
	* @param checkinHandler provides user input data to complete checkin process.
	* The keep-checked-out option supplied by this handler will be ignored if file is currently 
	* open in which case file will remain checked-out.
	* @param monitor the TaskMonitor.
	* @throws IOException if an IO or access error occurs
	* @throws VersionException if unable to handle domain object version in versioned filesystem.
	* We are unable to upgrade since this would only occur if checkout is not exclusive.
	* @throws CancelledException if task monitor cancelled operation
	*/
	public void checkin(CheckinHandler checkinHandler, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException;

	/**
	 * Performs check in to associated repository.  File must be checked-out 
	 * and modified since checkout.
	 * @param checkinHandler provides user input data to complete checkin process.
	 * This keep-checked-out option supplied by this handler will be ignored and forced true 
	 * if file is currently open.
	 * @param okToUpgrade if true an upgrade will be performed if needed (ignored)
	 * @param monitor the TaskMonitor.
	 * @throws IOException if an IO or access error occurs
	 * @throws VersionException if unable to handle domain object version in versioned filesystem.
	 * If okToUpgrade was false, check exception to see if it can be upgraded
	 * sometime after doing a checkout.
	 * @throws CancelledException if task monitor cancelled operation
	 * @deprecated use alternative {@link #checkin(CheckinHandler, TaskMonitor)} method since
	 * okToUpgrade cannot be respected and is ignored.  Upgrade cannot be performed during checkin.
	 */
	@Deprecated(since = "11.1", forRemoval = true)
	public default void checkin(CheckinHandler checkinHandler, boolean okToUpgrade,
			TaskMonitor monitor) throws IOException, VersionException, CancelledException {
		checkin(checkinHandler, monitor);
	}

	/**
	 * Performs merge from current version of versioned file into local checked-out file. 
	 * @param okToUpgrade if true an upgrade will be performed if needed
	 * @param monitor task monitor
	 * @throws IOException if an IO or access error occurs
	 * @throws VersionException if unable to handle domain object version in versioned filesystem.
	 * If okToUpgrade was false, check exception to see if it can be upgraded
	 * @throws CancelledException if task monitor cancelled operation
	 */
	public void merge(boolean okToUpgrade, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException;

	/**
	 * Undo "checked-out" file.  The original repository file is restored.
	 * @param keep if true, the private database will be renamed with a .keep
	 * extension.
	 * @throws NotConnectedException if shared project and not connected to repository
	 * @throws FileInUseException if this file is in-use.
	 * @throws IOException if file is not checked-out or an IO / access error occurs.
	 */
	public void undoCheckout(boolean keep) throws IOException;

	/**
	 * Undo "checked-out" file.  The original repository file is restored.
	 * @param keep if true, the private database will be renamed with a .keep
	 * extension.
	 * @param force if not connected to the repository the local checkout file will be removed.
	 *    Warning: forcing undo checkout will leave a stale checkout in place for the associated 
	 *    repository if not connected.
	 * @throws NotConnectedException if shared project and not connected to repository and
	 *    force is false
	 * @throws FileInUseException if this file is in-use / checked-out.
	 * @throws IOException thrown if file is not checked-out or an IO / access error occurs.
	 */
	public void undoCheckout(boolean keep, boolean force) throws IOException;

	/**
	 * Forcefully terminate a checkout for the associated versioned file.
	 * The user must be the owner of the checkout or have administrator privilege
	 * on the versioned filesystem (i.e., repository).
	 * @param checkoutId checkout ID
	 * @throws IOException if an IO or access error occurs
	 */
	public void terminateCheckout(long checkoutId) throws IOException;

	/**
	 * Get a list of checkouts by all users for the associated versioned file.
	 * @return list of checkouts
	 * @throws IOException if an IO or access error occurs
	 */
	public ItemCheckoutStatus[] getCheckouts() throws IOException;

	/**
	 * Get checkout status associated with a versioned file.
	 * @return checkout status or null if not checked-out to current associated project.
	 * @throws IOException if an IO or access error occurs
	 */
	public ItemCheckoutStatus getCheckoutStatus() throws IOException;

	/**
	 * Delete the entire database for this file, including any version files.
	 * @throws FileInUseException if this file is in-use / checked-out.
	 * @throws UserAccessException if the user does not have permission to delete the file.
	 * @throws IOException if an IO or access error occurs.
	 */
	public void delete() throws IOException;

	/**
	 * Deletes a specific version of a file from the versioned filesystem.  
	 * @param version specific version to be deleted.  The version must either
	 * be the oldest or latest, or -1 which will attempt to remove all versions.
	 * When deleting the latest version, this method could take a long time
	 * to return since the previous version must be reconstructed within the
	 * versioned filesystem.
	 * @throws IOException if an IO error occurs, including the inability 
	 * to delete a version because this item is checked-out, the user does
	 * not have permission, or the specified version is not the oldest or
	 * latest.
	 */
	void delete(int version) throws IOException;

	/**
	 * Move this file into the newParent folder.
	 * @param newParent new parent folder within the same project
	 * @return the newly relocated domain file (the original DomainFile object becomes invalid since it is immutable)
	 * @throws DuplicateFileException if a file with the same name 
	 * already exists in newParent folder.
	 * @throws FileInUseException if this file is in-use / checked-out.
	 * @throws IOException if an IO or access error occurs.
	 */
	public DomainFile moveTo(DomainFolder newParent) throws IOException;

	/**
	 * Copy this file into the newParent folder as a private file.
	 * @param newParent new parent folder
	 * @param monitor task monitor
	 * @return newly created domain file
	 * @throws FileInUseException if this file is in-use / checked-out.
	 * @throws IOException if an IO or access error occurs.
	 * @throws CancelledException if task monitor cancelled operation.
	 */
	public DomainFile copyTo(DomainFolder newParent, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Copy a specific version of this file to the specified destFolder.
	 * @param version version to copy
	 * @param destFolder destination parent folder
	 * @param monitor task monitor
	 * @return the copied file
	 * @throws IOException if an IO or access error occurs.
	 * @throws CancelledException if task monitor cancelled operation.
	 */
	public DomainFile copyVersionTo(int version, DomainFolder destFolder, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Copy this file into the newParent folder as a file-link.  A file-link references another
	 * file without actually copying all of its content.  If this file is associated with a 
	 * temporary transient project (i.e., not a locally managed project) the generated link will 
	 * refer to the this file with a Ghidra URL.  If this file is contained within the 
	 * same active {@link ProjectData} instance as {@code newParent} an internal link reference 
	 * will be made.
	 * 
	 * @param newParent new parent folder
	 * @param relative if true, and this file is contained within the same active 
	 * {@link ProjectData} instance as {@code newParent}, an internal-project relative path 
	 * file-link will be created.
	 * @return newly created domain file or null if content type does not support link use.
	 * @throws IOException if an IO or access error occurs.
	 */
	public DomainFile copyToAsLink(DomainFolder newParent, boolean relative) throws IOException;

	/**
	 * Determine if this file's content type supports linking.
	 * @return true if linking is supported, else false.
	 */
	public boolean isLinkingSupported();

	/**
	 * Get the list of consumers (Objects) for this domain file.
	 * @return true if linking is supported allowing a link-file to be created which 
	 * references this file, else false.
	 */
	public List<?> getConsumers();

	/**
	 * Return whether the domain object in this domain file has changed.
	 * @return true if changed
	 */
	public boolean isChanged();

	/**
	 * Returns true if there is an open domainObject for this file.
	 * @return true if open
	 */
	public boolean isOpen();

	/**
	 * Returns true if the domain object in this domain file exists and has an open transaction.
	 * @return true if busy
	 */
	public boolean isBusy();

	/**
	 * Pack domain file into specified file.
	 * Specified file will be overwritten if it already exists.
	 * @param file destination file
	 * @param monitor the task monitor
	 * @throws IOException if there is an exception packing the file
	 * @throws CancelledException if monitor cancels operation
	 */
	public void packFile(File file, TaskMonitor monitor) throws IOException, CancelledException;

	/**
	 * Returns an ordered map containing the metadata that has been associated with the 
	 * corresponding domain object. The map contains key,value pairs and are ordered by their 
	 * insertion order. 
	 * @return a map containing the metadata that has been associated with the corresponding domain 
	 * object.
	 */
	public Map<String, String> getMetadata();

	/**
	 * Returns the length of this domain file.  This size is the minimum disk space
	 * used for storing this file, but does not account for additional storage space
	 * used to track changes, etc. 
	 * @return file length
	 * @throws IOException if IO or access error occurs
	 */
	public long length() throws IOException;

	/**
	 * Determine if this file is a link-file which corresponds to either a file or folder link.  
	 * See {@link #getLinkInfo()} to obtain link information.
	 * <P>
	 * If the link-file is a {@link LinkFileInfo#isFolderLink() folder-link} the method 
	 * {@link LinkFileInfo#getLinkedFolder()} can be used to get the linked domain folder where the 
	 * resulting folder's {@link DomainFolder#isLinked()} indicates that it was the result of 
	 * following a folder-link.
	 * <P>
	 * The associated link path/URL may be obtained with {@link LinkFileInfo#getLinkPath()}.
	 * <P>
	 * The content type (see {@link #getContentType()} of a link-file will differ from that of the
	 * linked object (e.g., "LinkedProgram" vs "Program"). It is highly recommended that the 
	 * {@link #getDomainObjectClass()} method be used instead since it will return the same value 
	 * for a normal file or link-file that corresponds to the same {@link DomainObject} implementation.
	 * <P>
	 * The {@link DomainObject} referenced by a link-file may be opened using 
	 * {@link #getReadOnlyDomainObject(Object, int, TaskMonitor)}.  The 
	 * {@link #getDomainObject(Object, boolean, boolean, TaskMonitor)} method may also be used
	 * to obtain a read-only instance.  These methods should not be used on a folder-link since 
	 * an {@link UnsupportedOperationException} will be thrown.
	 * 
	 * @return true if link file else false for a normal domain file
	 */
	public boolean isLink();

	/**
	 * If this file is a {@link #isLink() link-file} the link information will be returned.
	 * @return link information or null if this is not a link-file
	 */
	public LinkFileInfo getLinkInfo();

}

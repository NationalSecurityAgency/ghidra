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

import javax.swing.Icon;

import db.DBHandle;
import ghidra.framework.model.ChangeSet;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.FolderItem;
import ghidra.util.InvalidNameException;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * NOTE:  ALL ContentHandler CLASSES MUST END IN "ContentHandler".  If not,
 * the ClassSearcher will not find them.
 * 
 * <code>ContentHandler</code> defines an application interface for converting 
 * between a specific domain object implementation and folder item storage. 
 * This interface also defines a method which provides an appropriate icon 
 * corresponding to the content.
 */
public interface ContentHandler extends ExtensionPoint {

	public static final String UNKNOWN_CONTENT = "Unknown-File";
	public static final String MISSING_CONTENT = "Missing-File";

	/**
	 * Creates a new folder item within a specified file-system.
	 * If fs is versioned, the resulting item is marked as checked-out
	 * within the versioned file-system.  The specified domainObj
	 * will become associated with the newly created database.
	 * @param fs the file system in which to create the folder item
	 * @param userfs file system which contains associated user data
	 * @param path the path of the folder item
	 * @param name the name of the new folder item
	 * @param domainObject the domain object to store in the newly created folder item
	 * @param monitor the monitor that allows the user to cancel
	 * @return checkout ID for new item
	 * @throws IOException if an i/o error occurs
	 * @throws InvalidNameException if the specified name contains invalid characters
	 * @throws CancelledException if the user cancels
	 */
	long createFile(FileSystem fs, FileSystem userfs, String path, String name,
			DomainObject domainObject, TaskMonitor monitor)
			throws IOException, InvalidNameException, CancelledException;

	/**
	 * Open a folder item for immutable use.  If any changes are attempted on the
	 * returned object, an IllegalStateException state exception may be thrown.
	 * @param item stored folder item
	 * @param consumer consumer of the returned object
	 * @param version version of the stored folder item to be opened.
	 * DomainFile.DEFAULT_VERSION (-1) should be specified when not opening a specific
	 * file version.
	 * @param minChangeVersion the minimum version which should be included in the 
	 * change set for the returned object. A value of -1 indicates the default change
	 * set.
	 * @param monitor the monitor that allows the user to cancel
	 * @return immutable domain object
	 * @throws IOException if a folder item access error occurs
	 * @throws CancelledException if operation is cancelled by user
	 * @throws VersionException if unable to handle file content due to version 
	 * difference which could not be handled.
	 */
	DomainObjectAdapter getImmutableObject(FolderItem item, Object consumer, int version,
			int minChangeVersion, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException;

	/**
	 * Open a folder item for read-only use.  While changes are permitted on the
	 * returned object, the original folder item may not be overwritten / updated.
	 * @param item stored folder item
	 * @param version version of the stored folder item to be opened.
	 * DomainFile.DEFAULT_VERSION should be specified when not opening a specific
	 * file version.
	 * @param okToUpgrade if true a version upgrade to the content will be done
	 * if necessary.
	 * @param consumer consumer of the returned object
	 * @param monitor the monitor that allows the user to cancel
	 * @return read-only domain object
	 * @throws IOException if a folder item access error occurs
	 * @throws CancelledException if operation is cancelled by user
	 * @throws VersionException if unable to handle file content due to version 
	 * difference which could not be handled.
	 */
	DomainObjectAdapter getReadOnlyObject(FolderItem item, int version, boolean okToUpgrade,
			Object consumer, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException;

	/**
	 * Open a folder item for update.  Changes made to the returned object may be
	 * saved to the original folder item.
	 * @param item stored folder item
	 * @param userfs file system which contains associated user data
	 * @param checkoutId an appropriate checout ID required to update the specified 
	 * folder item.
	 * @param okToUpgrade if true a version upgrade to the content will be done
	 * if necessary.
	 * @param okToRecover if true an attempt to recover any unsaved changes resulting from
	 * a crash will be attempted.
	 * @param consumer consumer of the returned object
	 * @param monitor cancelable task monitor
	 * @return updateable domain object
	 * @throws IOException if a folder item access error occurs
	 * @throws CancelledException if operation is cancelled by user
	 * @throws VersionException if unable to handle file content due to version 
	 * difference which could not be handled.
	 */
	DomainObjectAdapter getDomainObject(FolderItem item, FileSystem userfs, long checkoutId,
			boolean okToUpgrade, boolean okToRecover, Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException;

	/**
	 * Returns the object change data which includes changes made to the specified
	 * olderVersion through to the specified newerVersion.
	 * @param versionedFolderItem versioned folder item
	 * @param olderVersion the older version number
	 * @param newerVersion the newer version number
	 * @return the set of changes that were made 
	 * @throws VersionException if a database version change prevents reading of data.
	 * @throws IOException if a folder item access error occurs or change set was 
	 * produced by newer version of software and can not be read
	 */
	ChangeSet getChangeSet(FolderItem versionedFolderItem, int olderVersion, int newerVersion)
			throws VersionException, IOException;

	/**
	 * Get an instance of a suitable merge manager to be used during the merge of a Versioned 
	 * object which has been modified by another user since it was last merged
	 * or checked-out.
	 * @param resultsObj object to which merge results should be written
	 * @param sourceObj object which contains user's changes to be merged
	 * @param originalObj object which corresponds to checked-out version state
	 * @param latestObj object which corresponds to latest version with which
	 * the sourceObj must be merged.
	 * @return merge manager
	 */
	DomainObjectMergeManager getMergeManager(DomainObject resultsObj, DomainObject sourceObj,
			DomainObject originalObj, DomainObject latestObj);

	/**
	 * Returns true if the content type is always private 
	 * (i.e., can not be added to the versioned filesystem).
	 */
	boolean isPrivateContentType();

	/**
	 * Returns list of unique content-types supported.
	 * A minimum of one content-type will be returned. If more than one
	 * is returned, these are considered equivalent aliases.
	 */
	String getContentType();

	/**
	 * A string that is meant to be presented to the user.
	 */
	String getContentTypeDisplayString();

	/**
	 * Returns the Icon associated with this handlers content type.
	 */
	Icon getIcon();

	/**
	 * Returns the name of the default tool that should be used to open this content type
	 */
	String getDefaultToolName();

	/**
	 * Returns domain object implementation class supported.
	 */
	Class<? extends DomainObject> getDomainObjectClass();

	/**
	 * Create user data file associated with existing content.
	 * This facilitates the lazy creation of the user data file.
	 * @param associatedDomainObj associated domain object corresponding to this content handler
	 * @param userDbh user data handle
	 * @param userfs private user data filesystem
	 * @param monitor task monitor
	 * @throws IOException if an access error occurs
	 * @throws CancelledException if operation is cancelled by user
	 */
	void saveUserDataFile(DomainObject associatedDomainObj, DBHandle userDbh, FileSystem userfs,
			TaskMonitor monitor) throws CancelledException, IOException;

	/**
	 * Remove user data file associated with an existing folder item.
	 * @param item folder item
	 * @param userFilesystem
	 * @throws IOException if an access error occurs
	 */
	void removeUserDataFile(FolderItem item, FileSystem userFilesystem) throws IOException;

}

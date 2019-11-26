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
package ghidra.framework.store;

import java.io.File;
import java.io.IOException;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>FolderItem</code> represents an individual file
 * contained within a FileSystem and is uniquely identified 
 * by a path string.
 */
public interface FolderItem {

	/**
	 * Underlying file is an unknown/unsupported type.
	 */
	public static final int UNKNOWN_FILE_TYPE = -1;

	/**
	 * Underlying file is a Database
	 */
	public static final int DATABASE_FILE_TYPE = 0;

	/**
	 * Underlying file is serialized data file
	 */
	public static final int DATAFILE_FILE_TYPE = 1;

	/**
	 * Default checkout ID used when a checkout is not applicable.
	 */
	public static final long DEFAULT_CHECKOUT_ID = -1;

	/**
	 * Default file version number used to indicate the latest/current version.
	 */
	public static final int LATEST_VERSION = -1;

	/**
	 * Return The display name for this item.
	 */
	String getName();

	/**
	 * Return the file ID if one has been established or null
	 * @throws IOException thrown if IO or access error occurs
	 */
	String getFileID() throws IOException;

	/**
	 * Assign a new file-ID to this local non-versioned file.
	 * NOTE: This method is only valid for a local non-versioned file-system.
	 * @return new file-ID
	 * @throws IOException thrown if IO or access error occurs
	 */
	String resetFileID() throws IOException;

	/**
	 * Returns the length of this domain file.  This size is the minimum disk space
	 * used for storing this file, but does not account for additional storage space
	 * used to tracks changes, etc. 
	 * @return file length
	 * @throws IOException thrown if IO or access error occurs
	 */
	long length() throws IOException;

	/**
	 * Return The content type name for this item.
	 */
	String getContentType();

	/**
	 * Returns the path of the parent folder.
	 */
	String getParentPath();

	/**
	 * Return The concatenation of the pathname and the basename
	 * which can be used to uniquely identify a folder item.
	 */
	String getPathName();

	/**
	 * Returns true if item can be overwritten/deleted.
	 */
	boolean isReadOnly();

	/**
	 * Set the state of the read-only indicator for this non-shared item.
	 * @param state read-only state
	 * @throws IOException if an IO error occurs or item is 
	 * stored on a shared file-system
	 */
	void setReadOnly(boolean state) throws IOException;

	/**
	 * Returns the version of content type.  Note this is the version of the structure/storage
	 * for the content type, Not the users version of their data.
	 */
	int getContentTypeVersion();

	/**
	 * Sets the version for the content type. This will change whenever the domain objects
	 * are upgraded.
	 * @param version the new version for the content type.
	 * @throws IOException if an IO error occurs or item is 
	 * stored on a shared file-system
	 */
	void setContentTypeVersion(int version) throws IOException;

	/**
	 * Return The time that this item was last modified.
	 */
	long lastModified();

	/**
	 * Return the latest/current version.
	 */
	int getCurrentVersion();

	/**
	 * Returns true if this item is a checked-out copy from a versioned file system.
	 */
	boolean isCheckedOut();

	/**
	 * Returns true if this item is a checked-out copy with exclusive access from a versioned file system.
	 */
	boolean isCheckedOutExclusive();

	/**
	 * Return true if this is a versioned item, else false
	 * @throws IOException thrown if an IO error occurs.
	 */
	boolean isVersioned() throws IOException;

	/**
	 * Returns the checkoutId for this file.  A value of -1 indicates 
	 * a private item.
	 * NOTE: This method is only valid for a local non-versioned file-system.
	 * @throws IOException if an IO error occurs
	 */
	long getCheckoutId() throws IOException;

	/**
	 * Returns the item version which was checked-out.  A value of -1 indicates 
	 * a private item. 
	 * NOTE: This method is only valid for a local non-versioned file-system.
	 * @throws IOException
	 */
	int getCheckoutVersion() throws IOException;

	/**
	 * Returns the local item version at the time the checkout was
	 * completed.  A value of -1 indicates a private item.  
	 * NOTE: This method is only valid for a local non-versioned file-system.
	 */
	int getLocalCheckoutVersion();

	/**
	 * Set the checkout data associated with this non-shared file.
	 * NOTE: This method is only valid for a local non-versioned file-system.
	 * @param checkoutId checkout ID (provided by ItemCheckoutStatus).
	 * @param exclusive true if checkout is exclusive
	 * @param checkoutVersion the item version which was checked-out (provided
	 * by ItemCheckoutStatus).
	 * @param localVersion the local item version at the time the checkout was
	 * completed.
	 * @throws IOException if an IO error occurs or item is 
	 * stored on a shared file-system
	 */
	void setCheckout(long checkoutId, boolean exclusive, int checkoutVersion, int localVersion)
			throws IOException;

	/**
	 * Clears the checkout data associated with this non-shared file.
	 * NOTE: This method is only valid for a local non-versioned file-system.
	 * @throws IOException
	 */
	void clearCheckout() throws IOException;

	/**
	 * Deletes the item or a specific version.  If a specific version 
	 * is specified, it must either be the oldest or latest (i.e., current).
	 * @param version specific version to be deleted, or -1 to remove
	 * all versions.
	 * @param user user name
	 * @throws IOException if an IO error occurs, including the inability 
	 * to delete a version because this item is checked-out, the user does
	 * not have permission, or the specified version is not the oldest or
	 * latest.
	 */
	void delete(int version, String user) throws IOException;

	/**
	 * Returns list of all available versions or null
	 * if item is not versioned.
	 * @throws IOException thrown if an IO error occurs.
	 */
	Version[] getVersions() throws IOException;

	/**
	 * Checkout this folder item. 
	 * @param checkoutType type of checkout
	 * @param user user requesting checkout
	 * @param projectPath path of project where checkout was made
	 * @return checkout status or null if exclusive checkout request failed
	 * @throws IOException if an IO error occurs or this item is not versioned
	 */
	ItemCheckoutStatus checkout(CheckoutType checkoutType, String user, String projectPath)
			throws IOException;

	/**
	 * Terminates a checkout.  The checkout ID becomes invalid, therefore the 
	 * associated checkout copy should either be removed or converted to a
	 * private file.
	 * @param checkoutId checkout ID
	 * @param notify if true item change notification will be sent
	 * @throws IOException if an IO error occurs or this item is not versioned
	 */
	void terminateCheckout(long checkoutId, boolean notify) throws IOException;

	/**
	 * Returns true if this item is versioned and has one or more checkouts.
	 * @throws IOException if an IO error occurs
	 */
	boolean hasCheckouts() throws IOException;

	/**
	 * Returns true if unsaved file changes can be recovered.
	 */
	boolean canRecover();

	/**
	 * Get the checkout status which corresponds to the specified checkout ID.
	 * @param checkoutId checkout ID
	 * @return checkout status or null if checkout ID not found.
	 * @throws IOException if an IO error occurs or this item is not versioned
	 */
	ItemCheckoutStatus getCheckout(long checkoutId) throws IOException;

	/**
	 * Get all current checkouts for this item.
	 * @return array of checkouts
	 * @throws IOException if an IO error occurs or this item is not versioned
	 */
	ItemCheckoutStatus[] getCheckouts() throws IOException;

	/**
	 * Returns true if this item is versioned and has a checkin in-progress.
	 * @throws IOException if an IO error occurs
	 */
	boolean isCheckinActive() throws IOException;

	/**
	 * Update the checkout version associated with this versioned item.
	 * @param checkoutId id corresponding to an existing checkout
	 * @param checkoutVersion
	 * @param user
	 * @throws IOException if an IO error occurs.
	 */
	void updateCheckoutVersion(long checkoutId, int checkoutVersion, String user)
			throws IOException;

	/**
	 * Serialize (i.e., pack) this item into the specified outputFile.
	 * @param outputFile packed output file to be created
	 * @param version if this item is versioned, specifies the version to be output, otherwise
	 * -1 should be specified.
	 * @param monitor progress monitor
	 * @throws IOException
	 * @throws CancelledException if monitor cancels operation
	 */
	public void output(File outputFile, int version, TaskMonitor monitor) throws IOException,
			CancelledException;

	/**
	 * Returns this instance after refresh or null if item no longer exists
	 */
	public FolderItem refresh() throws IOException;

}

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
package ghidra.framework.remote;

import java.io.FileNotFoundException;
import java.io.IOException;

import db.buffers.ManagedBufferFileHandle;
import ghidra.framework.store.*;
import ghidra.util.InvalidNameException;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.exception.UserAccessException;

/**
 * <code>RepositoryHandle</code> provides access to a repository.
 */
public interface RepositoryHandle {

	// TODO: NOTE! Debugging client or sever garbage collection delays could
	// cause handle to be disposed prematurely.
	public final static int CLIENT_CHECK_PERIOD = SystemUtilities.isInTestingMode() ? 1000 : 30000;

	/**
	 * Returns the name of this repository.
	 * @throws IOException if an IO error occurs
	 */
	String getName() throws IOException;

	/**
	 * Returns user object associated with this handle.
	 * @throws IOException if an IO error occurs
	 */
	User getUser() throws IOException;

	/**
	 * Returns a list of users authorized for this repository.
	 * @throws UserAccessException
	 * @throws IOException if an IO error occurs
	 */
	User[] getUserList() throws IOException;

	/**
	 * @return true if anonymous access allowed by this repository
	 * @throws IOException if an IO error occurs
	 */
	boolean anonymousAccessAllowed() throws IOException;

	/**
	 * Convenience method for obtaining a list of all users
	 * known to the server.
	 * @return list of user names.
	 * @throws IOException if an IO error occurs
	 * @see RemoteRepositoryServerHandle#getAllUsers
	 */
	String[] getServerUserList() throws IOException;

	/**
	 * Set the list of authorized users for this repository.
	 * @param users list of user and access permissions.
	 * @param anonymousAccessAllowed true if anonymous access should be permitted to
	 * this repository
	 * @throws UserAccessException
	 * @throws IOException if an IO error occurs
	 */
	void setUserList(User[] users, boolean anonymousAccessAllowed) throws IOException;

	/**
	 * Get list of subfolders contained within the specified parent folder.
	 * @param folderPath parent folder path
	 * @return list of subfolder names
	 * @throws UserAccessException if user does not have adequate permission within the repository.
	 * @throws FileNotFoundException if specified parent folder path not found
	 * @throws IOException if an IO error occurs
	 */
	String[] getSubfolderList(String folderPath) throws IOException;

	/**
	 * Returns the number of folder items contained within this file-system.
	 * @throws IOException if an IO error occurs
	 * @throws UnsupportedOperationException if file-system does not support this operation
	 */
	int getItemCount() throws IOException;

	/**
	 * Get of all items found within the specified parent folder path.
	 * @param folderPath parent folder path
	 * @return list of items contained within specified parent folder
	 * @throws UserAccessException
	 * @throws FileNotFoundException if parent folder not found
	 * @throws IOException if an IO error occurs
	 */
	RepositoryItem[] getItemList(String folderPath) throws IOException;

	/**
	 * Returns the RepositoryItem in the given folder with the given name
	 * @param parentPath folder path
	 * @param name item name
	 * @return item or null if not found
	 * @throws IOException if an IO error occurs
	 */
	RepositoryItem getItem(String parentPath, String name) throws IOException;

	/**
	 * Returns the RepositoryItem with the given unique file ID
	 * @param fileID unique file ID
	 * @return item or null if not found
	 * @throws IOException if an IO error occurs
	 * @throws UnsupportedOperationException if file-system does not support this operation
	 */
	RepositoryItem getItem(String fileID) throws IOException;

	/**
	 * Create a new empty database item within the repository.
	 * @param parentPath parent folder path
	 * @param itemName new item name
	 * @param fileID unique file ID
	 * @param bufferSize buffer file buffer size
	 * @param contentType application content type
	 * @param projectPath path of user's project 
	 * @return initial buffer file open for writing 
	 * @throws UserAccessException if user does not have adequate permission within the repository.
	 * @throws DuplicateFileException item path already exists within repository
	 * @throws IOException if an IO error occurs
	 * @throws InvalidNameException if itemName or parentPath contains invalid characters
	 */
	ManagedBufferFileHandle createDatabase(String parentPath, String itemName, String fileID,
			int bufferSize, String contentType, String projectPath) throws IOException,
			InvalidNameException;

	/**
	 * Open an existing version of a database buffer file for non-update read-only use.
	 * @param parentPath parent folder path
	 * @param itemName name of existing data file
	 * @param version existing version of data file (-1 = latest version)
	 * @param minChangeDataVer indicates the oldest change data buffer file to be
	 * included.  A -1 indicates only the last change data buffer file is applicable.
	 * @return remote buffer file for non-update read-only use
	 * @throws UserAccessException if user does not have adequate permission within the repository.
	 * @throws FileNotFoundException if database version not found
	 * @throws IOException if an IO error occurs
	 */
	ManagedBufferFileHandle openDatabase(String parentPath, String itemName, int version,
			int minChangeDataVer) throws IOException;

	/**
	 * Open the current version for checkin of new version.
	 * @param parentPath parent folder path
	 * @param itemName name of existing data file
	 * @param checkoutId checkout ID
	 * @return remote buffer file for updateable read-only use
	 * @throws UserAccessException if user does not have adequate permission within the repository.
	 * @throws FileNotFoundException if database version not found
	 * @throws IOException if an IO error occurs
	 */
	ManagedBufferFileHandle openDatabase(String parentPath, String itemName, long checkoutId)
			throws IOException;

	/**
	 * Returns a list of all versions for the specified item.
	 * @param parentPath parent folder path
	 * @param itemName name of item
	 * @return version list
	 * @throws IOException if an IO error occurs
	 */
	Version[] getVersions(String parentPath, String itemName) throws IOException;

	/**
	 * Delete the specified version of an item.
	 * @param parentPath parent folder path
	 * @param itemName name of item
	 * @param version oldest or latest version of item to be deleted, or -1
	 * to delete the entire item.  User must be Admin or owner of version to be
	 * deleted.
	 * @throws IOException if an IO error occurs
	 */
	void deleteItem(String parentPath, String itemName, int version) throws IOException;

	/**
	 * Move an entire folder
	 * @param oldParentPath current parent folder path
	 * @param newParentPath new parent folder path
	 * @param oldFolderName current folder name
	 * @param newFolderName new folder name
	 * @throws InvalidNameException if newFolderName is invalid
	 * @throws DuplicateFileException if target folder already exists
	 * @throws IOException if an IO error occurs
	 */
	void moveFolder(String oldParentPath, String newParentPath, String oldFolderName,
			String newFolderName) throws InvalidNameException, IOException;

	/**
	 * Move an item to another folder
	 * @param oldParentPath current parent folder path
	 * @param newParentPath new parent folder path
	 * @param oldItemName current item name
	 * @param newItemName new item name
	 * @throws InvalidNameException if newItemName is invalid
	 * @throws DuplicateFileException if target item already exists
	 * @throws IOException if an IO error occurs
	 */
	void moveItem(String oldParentPath, String newParentPath, String oldItemName, String newItemName)
			throws InvalidNameException, IOException;

	/**
	 * Perform a checkout on the specified item.
	 * @param parentPath parent folder path
	 * @param itemName name of item
	 * @param checkoutType checkout type.  If exclusive or transient, checkout is only successful 
	 * if no other checkouts exist.  No new checkouts of item will be permitted while an 
	 * exclusive/transient checkout is active.
	 * @param projectPath path of user's project
	 * @return checkout data
	 * @throws IOException if an IO error occurs
	 */
	ItemCheckoutStatus checkout(String parentPath, String itemName, CheckoutType checkoutType,
			String projectPath) throws IOException;

	/**
	 * Terminate an existing item checkout.
	 * @param parentPath parent folder path
	 * @param itemName name of item
	 * @param checkoutId checkout ID
	 * @param notify notify listeners of item status change
	 * @throws IOException if an IO error occurs
	 */
	void terminateCheckout(String parentPath, String itemName, long checkoutId, boolean notify)
			throws IOException;

	/**
	 * Returns specific checkout data for an item.
	 * @param parentPath parent folder path
	 * @param itemName name of item
	 * @param checkoutId checkout ID
	 * @return checkout data
	 * @throws IOException if an IO error occurs
	 */
	ItemCheckoutStatus getCheckout(String parentPath, String itemName, long checkoutId)
			throws IOException;

	/**
	 * Get a list of all checkouts for an item.
	 * @param parentPath parent folder path
	 * @param itemName name of item
	 * @return checkout data list
	 * @throws IOException if an IO error occurs
	 */
	ItemCheckoutStatus[] getCheckouts(String parentPath, String itemName) throws IOException;

	/**
	 * Returns true if the specified folder path exists.
	 * @param folderPath folder path
	 * @throws IOException if an IO error occurs
	 */
	boolean folderExists(String folderPath) throws IOException;

	/**
	 * Returns true if the specified item exists.
	 * @param parentPath parent folder path
	 * @param itemName name of item
	 * @throws IOException if an IO error occurs
	 */
	boolean fileExists(String parentPath, String itemName) throws IOException;

	/**
	 * Returns the length of this domain file.  This size is the minimum disk space
	 * used for storing this file, but does not account for additional storage space
	 * used to tracks changes, etc. 
	 * @param parentPath parent folder path
	 * @param itemName name of item
	 * @return file length
	 * @throws IOException if an IO error occurs
	 */
	long getLength(String parentPath, String itemName) throws IOException;

	/**
	 * Returns true if the specified item has one or more checkouts.
	 * @param parentPath parent folder path
	 * @param itemName name of item
	 */
	boolean hasCheckouts(String parentPath, String itemName) throws IOException;

	/**
	 * Returns true if the specified item has an active checkin.
	 * @param parentPath parent folder path
	 * @param itemName name of item
	 */
	boolean isCheckinActive(String parentPath, String itemName) throws IOException;

	/**
	 * Update checkout data for an item following an update of a local checkout file.
	 * @param parentPath parent folder path
	 * @param itemName name of item
	 * @param checkoutId checkout ID
	 * @param checkoutVersion item version used for update
	 * @throws IOException if error occurs
	 */
	void updateCheckoutVersion(String parentPath, String itemName, long checkoutId,
			int checkoutVersion) throws IOException;

	/**
	 * Get pending change events.  Call will block until an event is available.
	 * @return array of events
	 * @throws IOException if error occurs.
	 */
	RepositoryChangeEvent[] getEvents() throws IOException;

	/**
	 * Notification to server that client is dropping handle.
	 * @throws IOException if error occurs
	 */
	void close() throws IOException;

}

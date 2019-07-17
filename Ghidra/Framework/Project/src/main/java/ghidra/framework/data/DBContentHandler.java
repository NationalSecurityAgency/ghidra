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

import db.DBHandle;
import db.buffers.BufferFile;
import db.buffers.ManagedBufferFile;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.*;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>DBContentHandler</code> provides an abstract ContentHandler for 
 * domain object content which is stored within a database file.
 * This class provides helper methods for working with database files.
 */
public abstract class DBContentHandler implements ContentHandler {

	/**
	 * Create a new database file from an open database handle.
	 * If fs is versioned, the resulting item is marked as checked-out
	 * within the versioned file-system.  The specified domainObj
	 * will become associated with the newly created database.
	 * @param domainObj domain object
	 * @param contentType the content type
	 * @param fs the domain object file system
	 * @param path the path of the new file
	 * @param name the name of the new file
	 * @param monitor the monitor that allows the user to cancel
	 * @return checkout ID for new file
	 * @throws InvalidNameException if the name contains invalid characters
	 * @throws CancelledException if the user cancels the operation
	 * @throws IOException if an i/o error occurs
	 */
	protected final long createFile(DomainObjectAdapterDB domainObj, String contentType,
			FileSystem fs, String path, String name, TaskMonitor monitor)
			throws InvalidNameException, CancelledException, IOException {
		DBHandle dbh = domainObj.getDBHandle();
		ManagedBufferFile bf =
			fs.createDatabase(path, name, FileIDFactory.createFileID(), contentType,
				dbh.getBufferSize(), SystemUtilities.getUserName(), null);
		long checkoutId = bf.getCheckinID();  // item remains checked-out after saveAs
		boolean success = false;
		try {
			dbh.saveAs(bf, true, monitor);
			success = true;
		}
		finally {
			if (!success) {
				try {
					bf.delete();
				}
				catch (IOException e) {
				}
				abortCreate(fs, path, name, checkoutId);
			}
		}
		return checkoutId;
	}

	private void abortCreate(FileSystem fs, String path, String name, long checkoutId) {
		try {
			FolderItem item = fs.getItem(path, name);
			if (item != null) {
				if (checkoutId != FolderItem.DEFAULT_CHECKOUT_ID) {
					item.terminateCheckout(checkoutId, false);
				}
				item.delete(-1, SystemUtilities.getUserName());
			}
		}
		catch (IOException e) {
			// Cleanup failed
		}
	}

	/**
	 * Return user data content type corresponding to associatedContentType.
	 */
	private static String getUserDataContentType(String associatedContentType) {
		return associatedContentType + "UserData";
	}

	/**
	 * @see ghidra.framework.data.ContentHandler#saveUserDataFile(ghidra.framework.model.DomainObject, db.DBHandle, ghidra.framework.store.FileSystem, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public final void saveUserDataFile(DomainObject domainObj, DBHandle userDbh, FileSystem userfs,
			TaskMonitor monitor) throws CancelledException, IOException {
		if (userfs.isVersioned()) {
			throw new IllegalArgumentException("User data file-system may not be versioned");
		}
		String associatedContentType = getContentType();
		DomainFile associatedDf = domainObj.getDomainFile();
		if (associatedDf == null) {
			throw new IllegalStateException("associated " + associatedContentType +
				" file must be saved before user data can be saved");
		}
		String associatedFileID = associatedDf.getFileID();
		if (associatedFileID == null) {
			Msg.error(this, associatedContentType + " '" + associatedDf.getName() +
				"' has not been assigned a file ID, user settings can not be saved!");
			return;
		}
		String path = "/";
		String name = ProjectFileManager.getUserDataFilename(associatedFileID);
		BufferFile bf = null;
		boolean success = false;
		try {
			bf =
				userfs.createDatabase(path, name, FileIDFactory.createFileID(),
					getUserDataContentType(associatedContentType), userDbh.getBufferSize(),
					SystemUtilities.getUserName(), null);
			userDbh.saveAs(bf, true, monitor);
			success = true;
		}
		catch (InvalidNameException e) {
			throw new AssertException("Unexpected Error", e);
		}
		finally {
			if (bf != null && !success) {
				try {
					bf.delete();
				}
				catch (IOException e) {
				}
				abortCreate(userfs, path, name, FolderItem.DEFAULT_CHECKOUT_ID);
			}
		}
	}

	/**
	 * @see ghidra.framework.data.ContentHandler#removeUserDataFile(ghidra.framework.store.FolderItem, ghidra.framework.store.FileSystem)
	 */
	@Override
	public final void removeUserDataFile(FolderItem associatedItem, FileSystem userfs)
			throws IOException {
		String path = "/";
		String name = ProjectFileManager.getUserDataFilename(associatedItem.getFileID());
		FolderItem item = userfs.getItem(path, name);
		if (item != null) {
			item.delete(-1, null);
		}
	}

	/**
	 * Open user data file associatedDbh
	 * @param associatedFileID
	 * @param associatedContentType
	 * @param userfs
	 * @param monitor
	 * @return user data file database handle
	 * @throws IOException
	 * @throws CancelledException
	 */
	protected final DBHandle openAssociatedUserFile(String associatedFileID,
			String associatedContentType, FileSystem userfs, TaskMonitor monitor)
			throws IOException, CancelledException {
		String path = "/";
		String name = ProjectFileManager.getUserDataFilename(associatedFileID);
		FolderItem item = userfs.getItem(path, name);
		if (item == null || !(item instanceof DatabaseItem) ||
			!getUserDataContentType(associatedContentType).equals(item.getContentType())) {
			return null;
		}
		DatabaseItem dbItem = (DatabaseItem) item;
		BufferFile bf = dbItem.openForUpdate(FolderItem.DEFAULT_CHECKOUT_ID);
		return new DBHandle(bf, false, monitor);
	}

}

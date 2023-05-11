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
 * 
 * @param <T> {@link DomainObjectAdapterDB} implementation class
 */
public abstract class DBWithUserDataContentHandler<T extends DomainObjectAdapterDB>
		extends DBContentHandler<T> {

	/**
	 * Return user data content type corresponding to associatedContentType.
	 */
	private static String getUserDataContentType(String associatedContentType) {
		return associatedContentType + "UserData";
	}

	/**
	 * Create user data file associated with existing content.
	 * This facilitates the lazy creation of the user data file.
	 * @param associatedDomainObj associated domain object corresponding to this content handler
	 * @param userDbh user data handle
	 * @param userfs private user data filesystem
	 * @param monitor task monitor
	 * @throws IOException if an IO or access error occurs
	 * @throws CancelledException if operation is cancelled by user
	 */
	public final void saveUserDataFile(DomainObject associatedDomainObj, DBHandle userDbh,
			FileSystem userfs,
			TaskMonitor monitor) throws CancelledException, IOException {
		if (userfs.isVersioned()) {
			throw new IllegalArgumentException("User data file-system may not be versioned");
		}
		String associatedContentType = getContentType();
		DomainFile associatedDf = associatedDomainObj.getDomainFile();
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
					// ignore
				}
				abortCreate(userfs, path, name, FolderItem.DEFAULT_CHECKOUT_ID);
			}
		}
	}

	/**
	 * Remove user data file associated with an existing folder item.
	 * @param associatedItem associated folder item
	 * @param userFilesystem user data file system from which corresponding data should be removed.
	 * @throws IOException if an access error occurs
	 */
	public final void removeUserDataFile(FolderItem associatedItem, FileSystem userFilesystem)
			throws IOException {
		String path = "/";
		String name = ProjectFileManager.getUserDataFilename(associatedItem.getFileID());
		FolderItem item = userFilesystem.getItem(path, name);
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

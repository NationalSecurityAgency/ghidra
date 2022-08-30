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
import db.buffers.ManagedBufferFile;
import ghidra.framework.store.*;
import ghidra.util.InvalidNameException;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>DBContentHandler</code> provides an abstract ContentHandler for 
 * domain object content which is stored within a database file.
 * This class provides helper methods for working with database files.
 * 
 * @param <T> {@link DomainObjectAdapterDB} implementation class
 */
public abstract class DBContentHandler<T extends DomainObjectAdapterDB>
		implements ContentHandler<T> {

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
					// ignore
				}
				abortCreate(fs, path, name, checkoutId);
			}
		}
		return checkoutId;
	}

	protected void abortCreate(FileSystem fs, String path, String name, long checkoutId) {
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

}

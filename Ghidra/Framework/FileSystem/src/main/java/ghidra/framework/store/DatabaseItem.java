/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.exception.FileInUseException;

import java.io.IOException;

import db.buffers.ManagedBufferFile;

/**
 * <code>DatabaseItem</code> corresponds to a private or versioned 
 * database within a FileSystem.  Methods are provided for opening
 * the underlying database as a BufferFile.
 */
public interface DatabaseItem extends FolderItem {
	
	/**
	 * Open a specific version of the stored database for non-update use.
	 * Historical change data from minChangeDataVer through version is available.
	 * The returned BufferFile does not support the BufferMgr's Save operation.
	 * @param version database version
	 * @param minChangeDataVer indicates the oldest change data version to be
	 * included in change set.  A -1 indicates only the last change data buffer file is applicable.
	 * @return buffer file
	 * @throws FileInUseException thrown if unable to obtain the required database lock(s).
	 * @throws IOException thrown if IO error occurs.
	 * @see ManagedBufferFile#getNextChangeDataFile(boolean)
	 */
	ManagedBufferFile open(int version, int minChangeDataVer) throws IOException;
	
	/**
	 * Open a specific version of the stored database for non-update use.
	 * Change data will not be available.
	 * The returned BufferFile does not support the BufferMgr's Save operation.
	 * @param version database version
	 * @return buffer file
	 * @throws FileInUseException thrown if unable to obtain the required database lock(s).
	 * @throws IOException thrown if IO error occurs.
	 */
	ManagedBufferFile open(int version) throws IOException;
	
	/**
	 * Open the current version of the stored database for non-update use.
	 * Change data will not be available.
	 * The returned BufferFile does not support the BufferMgr's Save operation.
	 * @throws IOException thrown if IO error occurs.
	 */
	ManagedBufferFile open() throws IOException;
	
	/**
	 * Open the current version of the stored database for update use.
	 * The returned BufferFile supports the Save operation.
	 * If this item is on a shared file-system, this method initiates an
	 * item checkin.  If a changeSet is specified, it will be filled with 
	 * all change data since the check-out version.  Change data will be 
	 * read into the change set starting oldest to newest.
	 * @param checkoutId the associated checkoutId if this item is stored
	 * on a versioned file-system, otherwise DEFAULT_CHECKOUT_ID can be 
	 * specified.
	 * @return buffer file
	 * @throws FileInUseException thrown if unable to obtain the required database lock(s).
	 * @throws IOException thrown if IO error occurs.
	 */
	ManagedBufferFile openForUpdate(long checkoutId) throws IOException;
}

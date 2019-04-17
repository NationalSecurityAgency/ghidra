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
package db.buffers;

import java.io.File;
import java.io.FileNotFoundException;

/**
 * <code>BufferFileManager</code> provides an interface for a 
 * BufferFile manager who understands the storage for the various
 * versions of BufferFiles associated with a single database.
 */
public interface BufferFileManager {

	/**
	 * Returns the current version.  A value of 0 indicates that the 
	 * first buffer file has not yet been created.
	 */
	int getCurrentVersion();

	/**
	 * Get the buffer file corresponding to a specified version.
	 * @param version
	 * @return database buffer file.
	 */
	File getBufferFile(int version);

	/**
	 * Get the buffer version file corresponding to a specified version.
	 * This file contains data corresponding to a specified buffer file version
	 * and those buffers which have been modified in the next version (version+1).
	 * May return null if version files not used.
	 * @param version version of the original buffer file to be reconstructed
	 * @return buffer version file.
	 */
	File getVersionFile(int version);

	/**
	 * Get the change data buffer file corresponding to the specified version.
	 * This file contains application specific changes which were made going from the 
	 * specified version to the next version (version+1).
	 * May return null if change data files are not used.
	 * @param version version of the original buffer file which was changed
	 * @return change data buffer file.
	 */
	File getChangeDataFile(int version);

	/**
	 * Returns the change map file corresponding to this DB if one is defined.
	 * This file tracks all buffers which have been modified during a save
	 * operation.
	 */
	File getChangeMapFile();

	/**
	 * Callback for when a buffer file is created.
	 * @param version
	 * @param comment
	 * @param checkinId associated checkinId
	 * @throws FileNotFoundException database files not found
	 */
	void versionCreated(int version, String comment, long checkinId) throws FileNotFoundException;

	/**
	 * Callback indicating that a buffer file update has ended without
	 * creating a new version.  This method terminates the checkin session.
	 * @param checkinId associated checkinId
	 */
	void updateEnded(long checkinId);

}

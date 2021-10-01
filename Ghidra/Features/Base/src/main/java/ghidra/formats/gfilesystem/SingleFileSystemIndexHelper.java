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
package ghidra.formats.gfilesystem;

import java.io.IOException;
import java.util.*;

/**
 * A helper class used by GFilesystem implementors that have a single file to handle lookups
 * and requests for that file.
 * <p>
 * This class is patterned on FileSystemIndexHelper and has pretty much the same api.
 */
public class SingleFileSystemIndexHelper {
	private GFile rootDir;
	private GFileImpl payloadFile;

	/**
	 * Creates a new instance.
	 *
	 * A "root" directory GFile will be auto-created for the filesystem.
	 * <p>
	 * @param fs the {@link GFileSystem} that this index will be for.
	 * @param fsFSRL the {@link FSRLRoot fsrl} of the filesystem itself.
	 * (this parameter is explicitly passed here so there is no possibility of trying to call
	 * back to the fs's {@link GFileSystem#getFSRL()} on a half-constructed filesystem.)
	 * @param payloadFilename name of the single file that this filesystem holds.
	 * @param length length of the payload file.
	 * @param payloadMD5 md5 of the payload file.
	 */
	public SingleFileSystemIndexHelper(GFileSystem fs, FSRLRoot fsFSRL, String payloadFilename,
			long length, String payloadMD5) {
		// NOTE: this impl should not call into the GFileSystem fs at this point
		// as it is probably being constructed at this time and not ready for callers yet.
		// The GFileImpl.fromFSRL(...)'s below do not call any methods on the FS, it is merely
		// used as the owner of the new GFileImpl instances.
		this.rootDir = GFileImpl.fromFSRL(fs, null, fsFSRL.withPath("/"), true, -1);
		this.payloadFile = GFileImpl.fromFSRL(fs, rootDir,
			rootDir.getFSRL().withPath(payloadFilename).withMD5(payloadMD5), false, length);
	}

	/**
	 * Clears the data held by this object.
	 */
	public void clear() {
		payloadFile = null;
	}

	/**
	 * Returns true if the specified file is the payload file.
	 * 
	 * @param file GFile to test
	 * @return boolean true if it is the payload file
	 */
	public boolean isPayloadFile(GFile file) {
		return payloadFile.equals(file);
	}

	/**
	 * Returns true if this object has been {@link #clear()}'ed.
	 *
	 * @return boolean true if data has been cleared.
	 */
	public boolean isClosed() {
		return payloadFile == null;
	}

	/**
	 * Gets the 'payload' file, ie. the main file of this filesystem.
	 *
	 * @return {@link GFile} payload file.
	 */
	public GFile getPayloadFile() {
		return payloadFile;
	}

	/**
	 * Gets the root dir's FSRL.
	 *
	 * @return {@link FSRL} of the root dir.
	 */
	public FSRL getRootDirFSRL() {
		return rootDir.getFSRL();
	}

	/**
	 * Gets the root {@link GFile} object for this filesystem index.
	 *
	 * @return root {@link GFile} object.
	 */
	public GFile getRootDir() {
		return rootDir;
	}

	/**
	 * Number of files in this index.
	 *
	 * @return number of file in this index.
	 */
	public int getFileCount() {
		return 1;
	}

	/**
	 * Mirror's {@link GFileSystem#getListing(GFile)} interface.
	 *
	 * @param directory {@link GFile} directory to get the list of child files that have been
	 * added to this index, null means root directory.
	 * @return {@link List} of GFile files that are in the specified directory, never null.
	 * @throws IOException if already closed.
	 */
	public List<GFile> getListing(GFile directory) throws IOException {
		if (isClosed()) {
			throw new IOException("Invalid state, index already closed");
		}
		if (directory == null || rootDir.equals(directory)) {
			return Arrays.asList(payloadFile);
		}
		return Collections.emptyList();
	}

	/**
	 * Mirror's {@link GFileSystem#lookup(String)} interface.
	 *
	 * @param path path and filename of a file to find (either "/" for root or the payload file's
	 * path).
	 * @return {@link GFile} instance or null if requested path is not the same as
	 * the payload file.
	 */
	public GFile lookup(String path) {
		if (path == null || path.equals("/")) {
			return rootDir;
		}
		else if (path.equals(payloadFile.getFSRL().getPath())) {
			return payloadFile;
		}
		return null;
	}

	@Override
	public String toString() {
		return "SingleFileSystemIndexHelper for " + rootDir.getFilesystem();
	}

}

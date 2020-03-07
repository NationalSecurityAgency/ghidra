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
package ghidra.framework.store.local;

import ghidra.framework.store.DataFileItem;
import ghidra.framework.store.FolderItem;
import ghidra.util.PropertyFile;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.TaskMonitor;

import java.io.*;

/**
 * <code>LocalDataFile</code> provides a FolderItem implementation
 * for a local serialized data file.  This implementation supports 
 * a non-versioned file-system only.
 * <p>
 * This item utilizes a data directory for storing the serialized 
 * data file.
 */
public class LocalDataFile extends LocalFolderItem implements DataFileItem {

	private final static int IO_BUFFER_SIZE = 32 * 1024;
	private static final String DATA_FILE = "data.1.gdf";

	public LocalDataFile(LocalFileSystem fileSystem, PropertyFile propertyFile) throws IOException {
		super(fileSystem, propertyFile, true, false);

		if (fileSystem.isVersioned()) {
			throw new IOException("Item may be corrupt: " + getName());
		}

		if (!getDataFile().exists()) {
			throw new FileNotFoundException(getName() + " not found");
		}
	}

	/**
	 * Create a new local data file item.
	 * @param fileSystem file system
	 * @param propertyFile serialized data property file
	 * @param istream data source input stream (should be a start of data and will be read to end of file).
	 * The invoker of this constructor is responsible for closing istream.
	 * @param contentType user content type
	 * @param monitor progress monitor (used for cancel support, 
	 * progress not used since length of input stream is unknown)
	 * @throws IOException if an IO Error occurs
	 * @throws CancelledException if monitor cancels operation
	 */
	public LocalDataFile(LocalFileSystem fileSystem, PropertyFile propertyFile,
			InputStream istream, String contentType, TaskMonitor monitor) throws IOException,
			CancelledException {
		super(fileSystem, propertyFile, true, true);

		if (fileSystem.isVersioned()) {
			abortCreate();
			throw new UnsupportedOperationException("Versioning not yet supported for DataFiles");
		}

		File dataFile = getDataFile();
		if (dataFile.exists()) {
			throw new DuplicateFileException(getName() + " already exists.");
		}
		propertyFile.putInt(FILE_TYPE, DATAFILE_FILE_TYPE);
		propertyFile.putBoolean(READ_ONLY, false);
		propertyFile.putString(CONTENT_TYPE, contentType);
		propertyFile.writeState();
		if (istream != null) {
			boolean success = false;
			byte[] buffer = new byte[IO_BUFFER_SIZE];
			FileOutputStream out = new FileOutputStream(dataFile);
			try {
				int cnt = 0;
				while ((cnt = istream.read(buffer)) >= 0) {
					out.write(buffer, 0, cnt);
				}
				success = true;
			}
			finally {
				try {
					out.close();
				}
				catch (IOException e) {
				}
				if (!success) {
					abortCreate();
				}
			}
		}
		else {
			if (!dataFile.createNewFile()) {
				abortCreate();
			}
		}
	}

	@Override
	public long length() throws IOException {
		return getDataFile().length();
	}

	/**
	 * Returns data File.
	 */
	private File getDataFile() {
		return new File(getDataDir(), DATA_FILE);
	}

	@Override
	public InputStream getInputStream() throws FileNotFoundException {
		return new FileInputStream(getDataFile());
	}

	@Override
	public InputStream getInputStream(int version) throws FileNotFoundException {

// TODO Versions for DataFiles are not supported

		return new FileInputStream(getDataFile());
	}

	@Override
	public OutputStream getOutputStream() throws FileNotFoundException {
		return new FileOutputStream(getDataFile());
	}

	@Override
	public void updateCheckout(FolderItem versionedFolderItem, boolean updateItem,
			TaskMonitor monitor) throws IOException {

		throw new UnsupportedOperationException("Versioning not yet supported for DataFiles");

	}

	@Override
	public void updateCheckout(FolderItem item, int checkoutVersion) throws IOException {

		throw new UnsupportedOperationException("Versioning not yet supported for DataFiles");

	}

	@Override
	void deleteMinimumVersion(String user) throws IOException {

		throw new UnsupportedOperationException("Versioning not yet supported for DataFiles");

	}

	@Override
	void deleteCurrentVersion(String user) throws IOException {

		throw new UnsupportedOperationException("Versioning not yet supported for DataFiles");

	}

	@Override
	public void output(File outputFile, int version, TaskMonitor monitor) throws IOException {

		throw new UnsupportedOperationException("Output not yet supported for DataFiles");

	}

	@Override
	int getMinimumVersion() throws IOException {
		return -1;
	}

	@Override
	public int getCurrentVersion() {
		return -1;
	}

	@Override
	public boolean canRecover() {
		return false;
	}

}

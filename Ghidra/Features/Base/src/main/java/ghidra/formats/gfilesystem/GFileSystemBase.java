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

import java.io.*;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

/**
 * This is the original GFileSystem implementation abstract base class, with most of the
 * initially implemented filesystem types extending this class.
 * <p>
 * The new GFileSystem interface is being retro-fitted into this equation to support
 * better probing and factory syntax, and new implementations should be based on
 * the interface instead of extending this abstract class.
 * <p>
 * NOTE:
 * ALL GFileSystem sub-CLASSES MUST END IN "FileSystem".
 * If not, the ClassSearcher will not find them.
 * Yes, it is an implementation detail.
 * <p>
 * GFileSystemBase instances are constructed when probing a container file and are queried
 * with {@link #isValid(TaskMonitor)} to determine if the container file is handled
 * by the GFileSystemBase subclass.<p>
 * The {@link ByteProvider} given to the constructor is not considered 'owned' by
 * the GFileSystemBase instance until after it passes the {@link #isValid(TaskMonitor) isValid}
 * check and is {@link #open(TaskMonitor) opened}.
 * <p>
 *
 */
public abstract class GFileSystemBase implements GFileSystem {

	protected String fileSystemName;
	protected GFileImpl root;
	protected ByteProvider provider;
	private FSRLRoot fsFSRL;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	protected FileSystemService fsService;

	protected GFileSystemBase(String fileSystemName, ByteProvider provider) {
		this.fileSystemName = fileSystemName;
		this.provider = provider;
	}

	@Override
	public String toString() {
		return "File system " + getType() + " - " + getDescription() + " - " + getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	public void setFSRL(FSRLRoot fsrl) {
		this.root = new GFileImpl(this, null, true, -1, fsrl.withPath("/"));
		this.fsFSRL = fsrl;
	}

	public void setFilesystemService(FileSystemService fsService) {
		this.fsService = fsService;
	}

	/**
	 * Returns true if this file system implementation
	 * can handle the bytes provided.
	 * This method should perform the minimal amount of
	 * checks required to determine validity.
	 * Keep it quick and tight!
	 * @param monitor a task monitor
	 * @return true if valid for the byte provider
	 * @throws IOException if an I/O error occurs
	 */
	abstract public boolean isValid(TaskMonitor monitor) throws IOException;

	/**
	 * Opens the file system.
	 * @throws IOException if an I/O error occurs
	 * @throws CryptoException if an encryption error occurs
	 */
	abstract public void open(TaskMonitor monitor)
			throws IOException, CryptoException, CancelledException;

	/**
	 * Closes the file system.
	 * All resources should be released. (programs, temporary files, etc.)
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void close() throws IOException {
		refManager.onClose();

		provider.close();
		provider = null;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	/**
	 * Returns the name of this file system.
	 * @return the name of this file system
	 */
	@Override
	final public String getName() {
		return fileSystemName;
	}

	@Override
	abstract public List<GFile> getListing(GFile directory) throws IOException;

	/**
	 * Legacy implementation of {@link #getInputStream(GFile, TaskMonitor)}.
	 *
	 * @param file {@link GFile} to get an InputStream for
	 * @param monitor {@link TaskMonitor} to watch and update progress
	 * @return new {@link InputStream} contains the contents of the file or NULL if the
	 * file doesn't have data.
	 * @throws IOException if IO problem
	 * @throws CancelledException if user cancels.
	 * @throws CryptoException if crypto problem.
	 */
	abstract protected InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException;

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws CancelledException, IOException {
		return getData(file, monitor);
	}

	/**
	 * Writes the given bytes to a tempfile in the temp directory.
	 * @param bytes the bytes to write
	 * @param fileName the prefix of the temp file name
	 */
	protected void debug(byte[] bytes, String fileName) {
		try {
			if (SystemUtilities.isInDevelopmentMode()) {
				File file = File.createTempFile(fileName, ".ghidra.tmp");
				OutputStream out = new FileOutputStream(file);
				try {
					out.write(bytes);
				}
				finally {
					out.close();
				}
			}
		}
		catch (IOException e) {//ignore...
		}
	}

	@Override
	public GFile lookup(String path) throws IOException {
		if (path == null || path.equals("/")) {
			return root;
		}
		GFile current = null;
		String[] parts = path.split("/");
		partloop: for (String part : parts) {
			if (part.isEmpty()) {
				continue;
			}
			List<GFile> listing = getListing(current);
			for (GFile gf : listing) {
				if (part.equals(gf.getName())) {
					current = gf;
					continue partloop;
				}
			}
			return null;
		}
		return current;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}
}

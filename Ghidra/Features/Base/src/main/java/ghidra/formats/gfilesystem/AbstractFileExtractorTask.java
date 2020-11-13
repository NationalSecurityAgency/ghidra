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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.exception.IOCancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Common base class for tasks that need to extract files from a GFileSystem location.
 * <p>
 *
 */
public abstract class AbstractFileExtractorTask extends Task {

	protected GFileSystem fs;
	protected File rootOutputDirectory;
	private int totalFilesExportedCount;
	private int totalDirsExportedCount;
	private long totalBytesExportedCount;

	/**
	 * See {@link Task#Task(String, boolean, boolean, boolean)}.
	 * 
	 * @param title See {@link Task#Task(String, boolean, boolean, boolean)}
	 * @param canCancel See {@link Task#Task(String, boolean, boolean, boolean)}
	 * @param hasProgress See {@link Task#Task(String, boolean, boolean, boolean)}
	 * @param isModal See {@link Task#Task(String, boolean, boolean, boolean)}
	 * @param rootOutputDir base directory where files will be extracted to
	 */
	public AbstractFileExtractorTask(String title, boolean canCancel, boolean hasProgress,
			boolean isModal, File rootOutputDir) {
		super(title, canCancel, hasProgress, isModal);
		this.rootOutputDirectory = rootOutputDir;
	}

	/**
	 * Starts the file extraction process.
	 * 
	 * @param fs the {@link GFileSystem} that holds the files
	 * @param srcDir the starting directory to extract, if {@code null}, start at root of file system
	 * @param monitor {@link TaskMonitor} that will be updated with progress and checked for cancel
	 * @throws CancelledException if the extraction is cancelled.
	 * @throws IOException if an exception occurs extracting the files.
	 */
	protected void startExtract(GFileSystem fs, GFile srcDir, TaskMonitor monitor)
			throws CancelledException, IOException {
		this.fs = fs;

		if (srcDir == null) {
			srcDir = fs.lookup(null);
		}
		processDirectory(srcDir, rootOutputDirectory, monitor);
	}

	/**
	 * Extract the contents of a directory in a {@link GFileSystem} into a local file system
	 * directory.
	 * <p>
	 * The destination directory is created if not present.
	 *
	 * @param srcGFileDirectory if null, directory is filesystem root
	 * @param destDirectory destination / output directory
	 * @param monitor {@link TaskMonitor} to watch and update with progress
	 * @throws IOException if IO problem.
	 * @throws CancelledException
	 */
	protected void processDirectory(GFile srcGFileDirectory, File destDirectory,
			TaskMonitor monitor) throws IOException, CancelledException {

		if (isSpecialDirectory(srcGFileDirectory)) {
			return;
		}

		if (!FileUtilities.isPathContainedWithin(rootOutputDirectory, destDirectory)) {
			// This can happen with hostile relative paths supplied by the data in the src filesystem.
			String srcPath = (srcGFileDirectory != null) ? srcGFileDirectory.getPath() : "/";
			throw new IOException("Extracted directory " + srcPath + " [" + destDirectory +
				"] would be outside of root destination directory: " + rootOutputDirectory);
		}

		if (!destDirectory.isDirectory() && !destDirectory.mkdirs()) {
			throw new IOException("Failed to create destination directory " + destDirectory);
		}
		totalDirsExportedCount++;

		for (GFile srcFile : fs.getListing(srcGFileDirectory)) {
			monitor.checkCanceled();

			String destFname = mapSourceFilenameToDest(srcFile);

			File destFSFile = new File(destDirectory, destFname);
			if (srcFile.isDirectory()) {
				processDirectory(srcFile, destFSFile, monitor);
			}
			else {
				processFile(srcFile, destFSFile, monitor);
			}
		}
	}

	protected void processFile(GFile srcFile, File destFSFile, TaskMonitor monitor)
			throws IOException, CancelledException {
		try {
			if (!FileUtilities.isPathContainedWithin(this.rootOutputDirectory, destFSFile)) {
				throw new IOException("Extracted file " + srcFile.getPath() + " [" + destFSFile +
					"] would be outside of root destination directory: " +
					this.rootOutputDirectory);
			}
			extractFile(srcFile, destFSFile.getCanonicalFile(), monitor);
		}
		catch (CancelledException | IOCancelledException e) {
			throw e;
		}
		catch (Exception e) {
			if (!handleUnexpectedException(srcFile, e)) {
				throw e;
			}
		}
	}

	/**
	 * Maps the untrusted, potentially hostile, filename of the source file to a name
	 * that is suitable to be used to create a file on the user's local file system.
	 * <p>
	 * NOTE: This base implementation converts relative directory names to spelled-out
	 * versions of that directory, eg. "." becomes "dot".
	 * <p>
	 * If you wish to modify this behavior, override this method and return different
	 * mappings.
	 *  
	 * @param srcFile source file
	 * @return String name of the source file, possibly modified to be safer
	 * @throws IOException thrown if name is not mappable and the extract process should stop
	 */
	protected String mapSourceFilenameToDest(GFile srcFile) throws IOException {
		return FSUtilities.getSafeFilename(srcFile.getName());
	}

	/**
	 * Allows custom handling of exceptions that occur during file extraction.
	 * <p>
	 * Return true if the exception should be ignored by the file extraction process,
	 * otherwise return false if it should be propagated up the call stack.
	 * 
	 * @param file file that was being extracted when the exception happened
	 * @param e the exception
	 * @return true if the exception should be suppressed, false if the exception should
	 * be thrown
	 */
	protected boolean handleUnexpectedException(GFile file, Exception e) {
		return false;
	}

	private boolean isSpecialDirectory(GFile directory) {
		if (directory == null) {
			return false;
		}

		switch (directory.getName()) {
			// Mac HFS metadata directories
			case "\0\0\0\0HFS+ Private Data":
			case ".HFS+ Private Directory Data\r":
				return true;
		}
		return false;
	}

	protected void extractFile(GFile srcFile, File outputFile, TaskMonitor monitor)
			throws CancelledException, CryptoException {

		monitor.setMessage(srcFile.getName());
		try (InputStream in = getSourceFileInputStream(srcFile, monitor)) {
			if (in != null) {
				try (OutputStream out = new FileOutputStream(outputFile)) {
					long bytesCopied = FileUtilities.copyStreamToStream(in, out, monitor);
					// only check the bytes copied if the file knows its length. If -1, just allow anything.
					if (srcFile.getLength() != -1 && bytesCopied != srcFile.getLength()) {
						throw new IOException("Failed to copy the correct number of bytes from " +
							srcFile.getFSRL() + " to " + outputFile + ".  Expected " +
							srcFile.getLength() + ", bytes copied " + bytesCopied);
					}
					totalBytesExportedCount += bytesCopied;
					totalFilesExportedCount++;
				}
			}
		}
		catch (IOException e) {
			Msg.error(this, "Error when copying file " + srcFile.getFSRL() + " to " + outputFile,
				e);
		}
	}

	protected InputStream getSourceFileInputStream(GFile file, TaskMonitor monitor)
			throws CancelledException, IOException {
		return fs.getInputStream(file, monitor);
	}

	/**
	 * Return the number of files that were exported.
	 * <p>
	 * @return the number of files that were exported
	 */
	public int getTotalFilesExportedCount() {
		return totalFilesExportedCount;
	}

	/**
	 * Return the number of directories that were exported.
	 * <p>
	 * @return the number of directories that were exported
	 */
	public int getTotalDirsExportedCount() {
		return totalDirsExportedCount;
	}

	/**
	 * Return the number of bytes that were exported.
	 * <p>
	 * @return the number of bytes that were exported
	 */
	public long getTotalBytesExportedCount() {
		return totalBytesExportedCount;
	}

}

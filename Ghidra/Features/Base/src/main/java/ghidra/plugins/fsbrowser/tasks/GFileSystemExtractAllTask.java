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
package ghidra.plugins.fsbrowser.tasks;

import java.awt.Component;
import java.io.*;
import java.util.LinkedHashMap;
import java.util.Map;

import docking.widgets.OptionDialog;
import ghidra.formats.gfilesystem.*;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * {@link Task} that recursively extracts all files from a {@link GFileSystem} directory
 * and writes them to a local filesystem.
 */
public class GFileSystemExtractAllTask extends Task {
	private FSRL srcFSRL;
	private File outputDirectory;
	private Component parentComponent;
	private int totalFilesExportedCount;
	private int totalDirExportedCount;
	private long totalBytesExportedCount;
	private boolean skipAllErrors;
	private Map<FSRL, String> errorredFiles = new LinkedHashMap<>();

	public GFileSystemExtractAllTask(FSRL srcFSRL, File outputDirectory,
			Component parentComponent) {
		super("Extracting directory...", true, false, true);
		this.srcFSRL = srcFSRL;
		this.outputDirectory = outputDirectory;
		this.parentComponent = parentComponent;
	}

	@Override
	public void run(TaskMonitor monitor) {
		long start_ts = System.currentTimeMillis();
		monitor.setMessage("Extracting all...");

		try (RefdFile refdFile = FileSystemService.getInstance().getRefdFile(srcFSRL, monitor)) {
			GFileSystem fs = refdFile.fsRef.getFilesystem();
			GFile file = refdFile.file;
			if (!file.isDirectory()) {
				Msg.warn(this, "Extract All source not a directory!  " + file.getFSRL());
				return;
			}

			File destDir = getDestDir(file.getName());
			if (destDir != null) {
				processDirectory(fs, file, destDir, monitor);
			}
		}
		catch (CancelledException ce) {
			Msg.warn(this, "Extract all task canceled");
		}
		catch (UnsupportedOperationException | IOException e) {
			Msg.showError(this, parentComponent, "Error extracting file", e.getMessage());
		}
		Msg.info(this, "Exported " + totalFilesExportedCount + " files, " + totalDirExportedCount +
			" directories, " + totalBytesExportedCount + " bytes");

		long elapsed = System.currentTimeMillis() - start_ts;

		//@formatter:off
		int option = OptionDialog.showOptionDialog(parentComponent, "Export Summary",
			"<html><div style='margin-bottom: 20pt; text-align: center; font-weight: bold'>Export files summary:</div>" +
					"<div style='margin-bottom: 20pt'>Source location:</div>" +
					"<div style='margin-bottom: 20pt; margin-left: 50pt'>" + HTMLUtilities.friendlyEncodeHTML(srcFSRL.toPrettyString()) + "</div>" +
					"<div style='margin-bottom: 20pt;'>Destination:</div>" +
					"<div style='margin-bottom: 20pt; margin-left: 50pt'>" + HTMLUtilities.friendlyEncodeHTML(outputDirectory.getPath() )+ "</div>" +
					"<div style='margin-bottom: 20pt;'>Elapsed time: " + DateUtils.formatDuration(elapsed) + "</div>" +
					"<table style='margin-bottom: 20pt;' width='100%'>" +
					"<tr><td></td><td>Files</td><td>Directories</td><td>Bytes</td></tr>" +
					"<tr><td>Successful</td><td>" + totalFilesExportedCount + "</td><td>" + totalDirExportedCount + "</td><td>" + FileUtilities.formatLength(totalBytesExportedCount) + "</td></tr>" +
					"<tr><td>Failed</td><td>" + errorredFiles.size() + "</td><td></td><td></td></tr>" +
					"</table>" +
					"</div></html>", "OK", "Show exported files");
		//@formatter:on
		if (option == OptionDialog.OPTION_TWO) {
			try {
				FileUtilities.openNative(outputDirectory);
			}
			catch (IOException e) {
				Msg.showError(this, parentComponent, "Problem Starting Explorer",
					"Problem starting file explorer: " + e.getMessage());
			}

		}
	}

	private File getDestDir(String destDirName) {
		boolean isSameName = destDirName.equals(outputDirectory.getName());
		File destDir = isSameName ? outputDirectory : new File(outputDirectory, destDirName);
		if (destDir.isFile()) {
			Msg.showError(this, parentComponent, "Export Destination Error",
				"Unable to export to " + destDir + " as it is a file");
			return null;
		}
		if (destDir.exists() && destDir.list().length > 0) {
			int answer = OptionDialog.showYesNoDialog(parentComponent, "Verify Export Destination",
				destDir.getAbsolutePath() + "\n" + "The directory is not empty." + "\n" +
					"Do you want to overwrite the contents?");
			if (answer == OptionDialog.NO_OPTION) {
				return null;
			}
		}
		return destDir;
	}

	/**
	 * Extract the contents of a directory in a {@link GFileSystem} into a local file system
	 * directory.
	 * <p>
	 * The destination directory is created if not present.
	 *
	 * @param fs the {@link GFileSystem} containing the directory.
	 * @param srcGFileDirectory if null, directory is filesystem root.
	 * @param destDirectory destination / output directory.
	 * @param monitor {@link TaskMonitor} to watch and update with progress.
	 * @throws IOException if IO problem.
	 */
	private void processDirectory(GFileSystem fs, GFile srcGFileDirectory, File destDirectory,
			TaskMonitor monitor) throws IOException, CancelledException {

		if (isSpecialDirectory(srcGFileDirectory)) {
			return;
		}

		if (!FileUtilities.isPathContainedWithin(outputDirectory, destDirectory)) {
			// This can happen with hostile relative paths supplied by the data in the filesystem.
			String srcPath = (srcGFileDirectory != null) ? srcGFileDirectory.getPath() : "/";
			throw new IOException("Extracted directory " + srcPath + " [" + destDirectory +
				"] would be outside of root destination directory: " + outputDirectory);
		}

		if (!destDirectory.isDirectory() && !destDirectory.mkdirs()) {
			throw new IOException("Failed to create destination directory " + destDirectory);
		}
		totalDirExportedCount++;

		for (GFile file : fs.getListing(srcGFileDirectory)) {
			monitor.checkCanceled();

			// TODO: maybe make this an optional safeguard to allow non-hostile relative paths
			// that safely stay inside the container
			String fname = FSUtilities.getSafeFilename(file.getName());

			File destFSFile = new File(destDirectory, fname);
			if (file.isDirectory()) {
				processDirectory(fs, file, destFSFile, monitor);
			}
			else {
				try {
					if (!FileUtilities.isPathContainedWithin(this.outputDirectory, destFSFile)) {
						throw new IOException("Extracted file " + file.getPath() + " [" +
							destFSFile + "] would be outside of root destination directory: " +
							this.outputDirectory);
					}
					extractFile(file, destFSFile.getCanonicalFile(), monitor);
				}
				catch (CancelledException | IOCancelledException e) {
					throw e;
				}
				catch (Exception e) {
					if (!handleUnexpectedException(file, e)) {
						throw e;
					}
				}
			}
		}
	}

	private boolean handleUnexpectedException(GFile file, Exception e) {
		errorredFiles.put(file.getFSRL(), e.getMessage());

		if (skipAllErrors) {
			return true;
		}

		int option = OptionDialog.showOptionDialog(parentComponent, "Error Extracting File",
			"There was a problem copying file " + file.getPath() + "\n\n" + e.getMessage() +
				"\n\nSkip this file and continue or cancel entire operation?",
			"Skip && Continue", "Skip All");
		if (option == OptionDialog.OPTION_TWO /* Skip All */) {
			skipAllErrors = true;
		}

		if (!skipAllErrors && option != OptionDialog.OPTION_ONE /* ie. != Skip this one*/) {
			return false;
		}
		return true;
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

	private void extractFile(GFile file, File outputFile, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {

		if (file.getLength() == 0) {
			return;
		}
		monitor.setMessage(file.getName());
		File cacheFile = FileSystemService.getInstance().getFile(file.getFSRL(), monitor);
		if (cacheFile == null) {
			return;
		}
		try (InputStream in = new FileInputStream(cacheFile);
				OutputStream out = new FileOutputStream(outputFile);) {
			long bytesCopied = FileUtilities.copyStreamToStream(in, out, monitor);
			if (file.getLength() != -1 && bytesCopied != file.getLength()) {
				throw new IOException("Failed to copy the correct number of bytes from " +
					file.getFSRL() + " to " + outputFile + ".  Expected " + file.getLength() +
					", bytes copied " + bytesCopied);
			}
			totalBytesExportedCount += bytesCopied;
			totalFilesExportedCount++;
		}
		catch (IOException e) {
			Msg.error(this, "Error when copying file " + file.getFSRL() + " to " + outputFile, e);
		}
	}
}

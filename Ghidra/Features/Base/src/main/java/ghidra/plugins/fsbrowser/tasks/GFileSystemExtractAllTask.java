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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;

import docking.widgets.OptionDialog;
import ghidra.formats.gfilesystem.AbstractFileExtractorTask;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.RefdFile;
import ghidra.util.DateUtils;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * {@link Task} that recursively extracts all files from a {@link GFileSystem} directory
 * and writes them to a local filesystem.
 */
public class GFileSystemExtractAllTask extends AbstractFileExtractorTask {
	private FSRL srcFSRL;
	private Component parentComponent;
	private boolean skipAllErrors;
	private Map<FSRL, String> errorredFiles = new LinkedHashMap<>();

	public GFileSystemExtractAllTask(FSRL srcFSRL, File outputDirectory,
			Component parentComponent) {
		super("Extracting directory...", true, false, true, outputDirectory);
		this.srcFSRL = srcFSRL;
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

			if (verifyRootOutputDir(file.getName())) {
				startExtract(fs, file, monitor);
			}
		}
		catch (CancelledException ce) {
			Msg.warn(this, "Extract all task canceled");
		}
		catch (UnsupportedOperationException | IOException e) {
			Msg.showError(this, parentComponent, "Error extracting file", e.getMessage());
		}
		Msg.info(this,
			"Exported " + getTotalFilesExportedCount() + " files, " + getTotalDirsExportedCount() +
				" directories, " + getTotalBytesExportedCount() + " bytes");

		long elapsed = System.currentTimeMillis() - start_ts;

		//@formatter:off
		int option = OptionDialog.showOptionDialog(parentComponent, "Export Summary",
			"<html><div style='margin-bottom: 20pt; text-align: center; font-weight: bold'>Export files summary:</div>" +
					"<div style='margin-bottom: 20pt'>Source location:</div>" +
					"<div style='margin-bottom: 20pt; margin-left: 50pt'>" + HTMLUtilities.friendlyEncodeHTML(srcFSRL.toPrettyString()) + "</div>" +
					"<div style='margin-bottom: 20pt;'>Destination:</div>" +
					"<div style='margin-bottom: 20pt; margin-left: 50pt'>" + HTMLUtilities.friendlyEncodeHTML(rootOutputDirectory.getPath() )+ "</div>" +
					"<div style='margin-bottom: 20pt;'>Elapsed time: " + DateUtils.formatDuration(elapsed) + "</div>" +
					"<table style='margin-bottom: 20pt;' width='100%'>" +
					"<tr><td></td><td>Files</td><td>Directories</td><td>Bytes</td></tr>" +
					"<tr><td>Successful</td><td>" + getTotalFilesExportedCount() + "</td><td>" + getTotalDirsExportedCount() + 
						"</td><td>" + FileUtilities.formatLength(getTotalBytesExportedCount()) + "</td></tr>" +
					"<tr><td>Failed</td><td>" + errorredFiles.size() + "</td><td></td><td></td></tr>" +
					"</table>" +
					"</div></html>", "OK", "Show exported files");
		//@formatter:on
		if (option == OptionDialog.OPTION_TWO) {
			try {
				FileUtilities.openNative(rootOutputDirectory);
			}
			catch (IOException e) {
				Msg.showError(this, parentComponent, "Problem Starting Explorer",
					"Problem starting file explorer: " + e.getMessage());
			}

		}
	}

	private boolean verifyRootOutputDir(String destDirName) {
		boolean isSameName = destDirName.equals(rootOutputDirectory.getName());
		File newRootOutputDir =
			isSameName ? rootOutputDirectory : new File(rootOutputDirectory, destDirName);
		if (newRootOutputDir.isFile()) {
			Msg.showError(this, parentComponent, "Export Destination Error",
				"Unable to export to " + newRootOutputDir + " as it is a file");
			return false;
		}
		if (newRootOutputDir.exists() && newRootOutputDir.list().length > 0) {
			int answer = OptionDialog.showYesNoDialog(parentComponent, "Verify Export Destination",
				newRootOutputDir.getAbsolutePath() + "\n" + "The directory is not empty." + "\n" +
					"Do you want to overwrite the contents?");
			if (answer == OptionDialog.NO_OPTION) {
				return false;
			}
		}
		rootOutputDirectory = newRootOutputDir;
		return true;
	}

	@Override
	protected boolean handleUnexpectedException(GFile file, Exception e) {
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

	@Override
	protected InputStream getSourceFileInputStream(GFile file, TaskMonitor monitor)
			throws CancelledException, IOException {
		File cacheFile = FileSystemService.getInstance().getFile(file.getFSRL(), monitor);
		return new FileInputStream(cacheFile);
	}

}

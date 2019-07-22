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
package ghidra.app.plugin.core.archive;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Set;

import javax.swing.SwingUtilities;

import org.apache.commons.io.FilenameUtils;

import ghidra.formats.gfilesystem.AbstractFileExtractorTask;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.util.Msg;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Task that restores a Ghidra Project Archive file (a zip file with a .gar extension)
 *
 */
class RestoreTask extends AbstractFileExtractorTask {

	// files that should always be skipped when extracting the zip file
	private static final Set<String> FILES_TO_SKIP = Set.of( //
		"/" + ArchivePlugin.JAR_VERSION_TAG.toLowerCase(),
		"/" + ArchivePlugin.PROJECT_PROPERTY_FILE.toLowerCase(),
		"/" + ArchivePlugin.PROJECT_STATE_FILE.toLowerCase(),
		"/" + ArchivePlugin.OLD_PROJECT_SAVE_DIR.toLowerCase(),
		"/" + ArchivePlugin.OLD_PROJECT_GROUPS_DIR.toLowerCase());

	private File projectArchiveFile;
	private ProjectLocator projectLocator;
	private ArchivePlugin plugin;
	private File projectFile;
	private File projectDir;

	RestoreTask(ProjectLocator projectLocator, File projectArchiveFile, ArchivePlugin plugin) {
		super("Restoring Project: " + projectLocator.getName(), true, false, true,
			projectLocator.getProjectDir());
		this.projectLocator = projectLocator;
		this.projectArchiveFile = projectArchiveFile;
		this.plugin = plugin;

		this.projectFile = projectLocator.getMarkerFile();
		this.projectDir = projectLocator.getProjectDir();

	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		FileSystemService fsService = FileSystemService.getInstance();
		String locInfo = "\"" + projectLocator.toString() + "\" from \"" +
			projectArchiveFile.getAbsolutePath() + "\"";

		if (projectFile.exists() || projectDir.exists()) {
			Msg.showError(this, null, "Restore Archive Error",
				"Project already exists at: " + projectDir);
			return;
		}

		FSRL archiveFSRL = fsService.getLocalFSRL(projectArchiveFile);
		try (GFileSystem fs = fsService.openFileSystemContainer(archiveFSRL, monitor)) {
			verifyArchive(fs, monitor);
			startExtract(fs, null, monitor);
			createProjectMarkerFile();
			openRestoredProject();
			Msg.info(this, "Restore Archive: " + locInfo + " succeeded.");
		}
		catch (CancelledException ce) {
			plugin.cleanupRestoredProject(projectLocator);
			Msg.info(this, "Restore Archive: " + locInfo + " was cancelled by user.");
		}
		catch (Throwable e) {
			plugin.cleanupRestoredProject(projectLocator);
			String eMsg = (e.getMessage() != null) ? ":\n\n" + e.getMessage() : "";
			Msg.showError(this, null, "Restore Archive Failed",
				"An error occurred when restoring the project archive\n " + projectArchiveFile +
					" to \n " + projectDir + eMsg,
				e);
			Msg.info(this, "Restore Archive: " + locInfo + " failed.");
		}
	}

	private void createProjectMarkerFile() throws IOException {
		if (!projectFile.createNewFile()) {
			throw new IOException("Couldn't create file " + projectFile.getAbsolutePath());
		}
	}

	private void verifyArchive(GFileSystem fs, TaskMonitor monitor) throws IOException {
		if (!fs.getFSRL().getProtocol().equals("zip")) {
			throw new IOException("Not a zip file: " + fs.getFSRL());
		}
		GFile magicFile = fs.lookup("/" + ArchivePlugin.JAR_VERSION_TAG);
		if (magicFile == null) {
			throw new IOException("Missing Ghidra Project Archive (.gar) marker file");
		}
	}

	@Override
	protected void processFile(GFile file, File destFSFile, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!shouldSkip(file)) {
			super.processFile(file, destFSFile, monitor);
		}
	}

	@Override
	protected void processDirectory(GFile srcGFileDirectory, File destDirectory,
			TaskMonitor monitor) throws IOException, CancelledException {
		if (!shouldSkip(srcGFileDirectory)) {
			super.processDirectory(srcGFileDirectory, destDirectory, monitor);
		}
	}

	@Override
	protected String mapSourceFilenameToDest(GFile srcFile) throws IOException {
		String filename = srcFile.getName();
		if (!FSUtilities.getSafeFilename(filename).equals(filename)) {
			throw new IOException("Bad filename in archive: \"" + filename + "\"");
		}
		return filename;
	}

	private boolean shouldSkip(GFile file) {
		String path = file.getPath().toLowerCase();
		if (FILES_TO_SKIP.contains(path)) {
			return true;
		}
		if (ArchivePlugin.OLD_FOLDER_PROPERTIES_FILE.equalsIgnoreCase(file.getName())) {
			// ignore this file in any directory in the archive
			return true;
		}
		String ext = "." + FilenameUtils.getExtension(file.getName());
		if (GhidraURL.MARKER_FILE_EXTENSION.equalsIgnoreCase(ext)) {
			// ignore .gpr marker files, any file name
			return true;
		}
		return false;
	}

	private void openRestoredProject() {
		try {
			SwingUtilities.invokeAndWait(() -> {
				ProjectManager pm = plugin.getTool().getProjectManager();
				try {
					Project project = pm.openProject(projectLocator, true, true);
					pm.rememberProject(projectLocator);
					FrontEndTool tool = (FrontEndTool) plugin.getTool();
					tool.setActiveProject(project);
				}
				catch (NotOwnerException e) {
					// can't happen since resetOwner is true
				}
				catch (Exception e) {
					Msg.info(this,
						"Restore Archive: Error opening project: " + projectLocator.getName());

					Msg.showError(this, null, "Restore Archive Error",
						"Failed to open newly restored project", e);
				}
			});
		}
		catch (InvocationTargetException | InterruptedException e) {
			// ignore
		}
	}
}

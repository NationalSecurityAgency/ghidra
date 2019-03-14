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

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.util.jar.JarInputStream;

import javax.swing.SwingUtilities;

import generic.io.JarReader;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.*;
import ghidra.util.Msg;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

class RestoreTask extends Task {

	private File jarFile;
	private ProjectLocator projectLocator;
	private ArchivePlugin plugin;
	private String message;

	RestoreTask(ProjectLocator projectLocator, File inJarFile, ArchivePlugin plugin) {
		super("Restoring Project: " + projectLocator.getName(), true, false, true);
		this.projectLocator = projectLocator;
		jarFile = inJarFile;
		this.plugin = plugin;
	}

	@Override
	public void run(TaskMonitor monitor) {
		boolean ok = false;
		try {
			unjarArchive(monitor);
			ok = true;
		}
		catch (Exception e) {
			Msg.showError(this, null, null, null, e);
			message = message + " failed.";
		}
		message =
			"\"" + projectLocator.toString() + "\" from \"" + jarFile.getAbsolutePath() + "\"";
		if (monitor.isCancelled()) {
			message += " was cancelled by user.";
			// put everything back the way it was...
			plugin.cleanupRestoredProject(projectLocator);
		}
		else {
			message += ((ok) ? " succeeded." : " failed.");
			final boolean success = ok;
			Runnable r = () -> restoreCompleted(success);
			try {
				SwingUtilities.invokeAndWait(r);
			}
			catch (InterruptedException e1) {
			}
			catch (InvocationTargetException e1) {
			}
		}

		Msg.info(this, "Restore Archive: " + message);
	}

	/**
	 * Unjar the archive file.
	 * @param monitor 
	 * @throws IOException
	 */
	private void unjarArchive(TaskMonitor monitor) throws IOException {
		JarInputStream jarIn = new JarInputStream(new FileInputStream(jarFile));
		JarReader reader = new JarReader(jarIn);

		// position input stream to the entry after the .gpr entry since
		// we don't want to create that file
		jarIn.getNextJarEntry();

		// the next entry should be JAR_FORMAT
		jarIn.getNextJarEntry();

		File projectFile = projectLocator.getMarkerFile();
		File projectDir = projectLocator.getProjectDir();
		if (projectFile.exists()) {
			throw new DuplicateFileException("Project already exists: " + projectFile);
		}
		if (projectDir.exists()) {
			throw new DuplicateFileException("Project already exists: " + projectDir);
		}

		reader.createRecursively(projectDir.getAbsolutePath() + File.separator, monitor);

		jarIn.close();
		if (monitor.isCancelled()) {
			return;
		}

		// Remove unwanted project properties file - will get re-created when project is opened
		File file = new File(projectDir, ArchivePlugin.PROJECT_PROPERTY_FILE);
		file.delete();

		// Remove unwanted project state file
		file = new File(projectDir, ArchivePlugin.PROJECT_STATE_FILE);
		file.delete();

		// Remove unwanted project state save directory
		file = new File(projectDir, ArchivePlugin.OLD_PROJECT_SAVE_DIR);
		FileUtilities.deleteDir(file);

		// Remove unwanted project groups directory
		file = new File(projectDir, ArchivePlugin.OLD_PROJECT_GROUPS_DIR);
		FileUtilities.deleteDir(file);

		// Remove unwanted folder property files
		removeOldFolderProperties(projectDir);

		// create the .gpr file for the new project

		if (!projectFile.createNewFile()) {
			throw new IOException("Couldn't create file " + projectFile.getAbsolutePath());
		}
	}

	private static void removeOldFolderProperties(File dir) {

		File f = new File(dir, ArchivePlugin.OLD_FOLDER_PROPERTIES_FILE);
		f.delete();

		File[] files = dir.listFiles();
		for (File file : files) {
			if (file.isDirectory()) {
				removeOldFolderProperties(file);
			}
		}
	}

	private void restoreCompleted(boolean ok) {
		if (ok) {
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
				message = "Error opening project: " + projectLocator.getName();
				Msg.showError(this, null, null, null, e);
			}
		}
		else {
			plugin.cleanupRestoredProject(projectLocator);
		}
	}
}

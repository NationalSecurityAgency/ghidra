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
package ghidra.app.plugin.core.archive;

import generic.io.JarWriter;
import ghidra.framework.model.Project;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

class ArchiveTask extends Task {

	private File jarFile;
	private Project project;
	private String projectName;

	// TODO -- fix constructor to take the active project...
	ArchiveTask(Project project, File outJarFile) {
		super("Archiving Project: " + project.getName(), true, false, true);
		this.project = project;
		jarFile = outJarFile;
		projectName = project.getName();
	}

	@Override
	public void run(TaskMonitor monitor) {
		boolean ok = false;
		try {
			monitor.setMessage("Begin archiving...");
			ok = writeProject(monitor);
		}
		catch (Exception e) {
			Msg.showError(this, null, null, null, e);
		}
		String message =
			"Archiving \"" + project.getName() + "\" to \"" + jarFile.getAbsolutePath() + "\"";
		if (monitor.isCancelled()) {
			message += " was cancelled by user.";
		}
		else {
			message += (ok) ? " succeeded." : " failed.";
		}
		Msg.info(this, message);
		if (!ok) {
			if (jarFile.exists() && !jarFile.delete()) {
				Msg.error(this, "Couldn't remove bad jar file (" + jarFile.getAbsolutePath() + ")");
			}
		}
	}

	/**
	 * Write project out to the jar file.
	 * @param monitor monitor that can be cancelled
	 * @return true if no errors occurred within the JarWriter object
	 * @throws IOException
	 */
	private boolean writeProject(TaskMonitor monitor) throws IOException {
		boolean ok = false;

		JarOutputStream jarOut = new JarOutputStream(new FileOutputStream(jarFile));
		// exclude the lock files on programs
		JarWriter writer = new JarWriter(jarOut, new String[] { ArchivePlugin.DB_LOCK_EXT });
		String archiveComment = "Ghidra archive file for " + projectName + " project.";
		jarOut.setComment(archiveComment);
		// write the .gpr file 
		File projectFile = project.getProjectLocator().getMarkerFile();
		ok = writer.outputFile(projectFile, "", monitor);
		if (ok) {
			// write an indicator that this is jar format vs writing XML files
			ZipEntry entry = new ZipEntry(ArchivePlugin.JAR_VERSION_TAG);
			jarOut.putNextEntry(entry);

			ok = writeProjectDirs(writer, monitor);

		}
		jarOut.close();
		return ok;
	}

	private boolean writeProjectDirs(JarWriter writer, TaskMonitor monitor) {
		File projectFolder = project.getProjectLocator().getProjectDir();
		String[] names = projectFolder.list();
		for (int i = 0; i < names.length; i++) {
			if (monitor.isCancelled()) {
				return false;
			}
			File file = new File(projectFolder, names[i]);
			monitor.setMessage("Writing " + file.getAbsolutePath());
			if (file.isDirectory()) {
				if (!writer.outputRecursively(file, "", monitor)) {
					return false;
				}
			}
		}
		return true;
	}

}

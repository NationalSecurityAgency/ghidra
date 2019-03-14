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
package ghidra.framework.data;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.store.local.*;

public class ConvertFileSystem implements GhidraLaunchable {

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) {

		MessageListener msgListener = string -> System.out.println(string);

		try {
			File dir = getDir(args.length == 0 ? null : args[0]);
			if (dir.getName().endsWith(".rep")) {
				convertProject(dir, msgListener);
			}
			else {
				convertRepositories(dir, msgListener);
			}
		}
		catch (ConvertFileSystemException e) {
			System.err.println(e.getMessage());
		}
	}

	public static interface MessageListener {
		public void println(String string);
	}

	public static class ConvertFileSystemException extends IOException {
		public ConvertFileSystemException() {
			super();
		}

		public ConvertFileSystemException(String message) {
			super(message);
		}

		public ConvertFileSystemException(String message, Throwable cause) {
			super(message, cause);
		}
	}

	private static File getDir(String path) throws ConvertFileSystemException {
		if (path == null) {
			throw new ConvertFileSystemException(
				"Must specify a project (*.rep) or server repositories directory");
		}
		File dir = new File(path);
		if (!dir.isDirectory()) {
			throw new ConvertFileSystemException(
				"Invalid project or repositories directory specified: " + dir);
		}
		return dir;
	}

	private static void convertRepositories(File dir, MessageListener msgListener)
			throws ConvertFileSystemException {
		File file = new File(dir, "~admin");
		if (!file.isDirectory()) {
			throw new ConvertFileSystemException(
				"Invalid repositories directory specified (~admin not found): " + dir);
		}
		file = new File(dir, "users");
		if (!file.isFile()) {
			throw new ConvertFileSystemException(
				"Invalid repositories directory specified (users not found): " + dir);
		}
		file = new File(dir, "server.log");
		if (!file.isFile()) {
			throw new ConvertFileSystemException(
				"Invalid repositories directory specified (server.log not found): " + dir);
		}
		List<File> repoDirs = new ArrayList<>();
		for (File f : dir.listFiles()) {
			// look for repository directories
			if (!f.isDirectory() || LocalFileSystem.isHiddenDirName(f.getName())) {
				continue;
			}
			repoDirs.add(f);
		}
		msgListener.println("Converting " + repoDirs.size() + " repositories...");
		for (File repoDir : repoDirs) {
			convertRepo(repoDir, msgListener);
		}
	}

	private static void convertRepo(File repoDir, MessageListener msgListener)
			throws ConvertFileSystemException {
		try {
			LocalFileSystem fs = LocalFileSystem.getLocalFileSystem(repoDir.getAbsolutePath(),
				false, true, false, false);
			if (fs instanceof MangledLocalFileSystem) {
				MangledLocalFileSystem mfs = (MangledLocalFileSystem) fs;
				msgListener.println("Converting repository directory: " + repoDir);
				mfs.convertToIndexedLocalFileSystem();
			}
			else if ((fs instanceof IndexedLocalFileSystem) &&
				((IndexedLocalFileSystem) fs).getIndexImplementationVersion() < IndexedLocalFileSystem.LATEST_INDEX_VERSION) {
				msgListener.println("Rebuilding Index for repository directory (" +
					fs.getItemCount() + " files): " + repoDir);
				fs.dispose();
				IndexedV1LocalFileSystem.rebuild(repoDir);
			}
			else {
				msgListener.println(
					"Repository directory has previously been converted: " + repoDir);
			}
		}
		catch (IOException e) {
			if (e instanceof ConvertFileSystemException) {
				throw (ConvertFileSystemException) e;
			}
			throw new ConvertFileSystemException(
				"Error converting repository directory (" + repoDir + "): " + e.getMessage(), e);
		}
	}

	private static void convertProjectDir(File dir, String dirType, MessageListener msgListener)
			throws ConvertFileSystemException {
		try {
			LocalFileSystem fs = LocalFileSystem.getLocalFileSystem(dir.getAbsolutePath(), false,
				false, false, false);
			if (fs instanceof MangledLocalFileSystem) {
				MangledLocalFileSystem mfs = (MangledLocalFileSystem) fs;
				msgListener.println("Converting " + dirType + " directory: " + dir);
				mfs.convertToIndexedLocalFileSystem();
			}
			else if ((fs instanceof IndexedLocalFileSystem) &&
				((IndexedLocalFileSystem) fs).getIndexImplementationVersion() < IndexedLocalFileSystem.LATEST_INDEX_VERSION) {
				msgListener.println("Rebuilding Index for " + dirType + " directory (" +
					fs.getItemCount() + " files): " + dir);
				fs.dispose();
				IndexedV1LocalFileSystem.rebuild(dir);
			}
			else if (fs instanceof IndexedLocalFileSystem) {
				msgListener.println(
					"Project " + dirType + " directory has previously been converted: " + dir);
			}
		}
		catch (IOException e) {
			if (e instanceof ConvertFileSystemException) {
				throw (ConvertFileSystemException) e;
			}
			throw new ConvertFileSystemException("Error converting project " + dirType +
				" directory (" + dir + "): " + e.getMessage(), e);
		}
	}

	public static void convertProject(File dir, MessageListener msgListener)
			throws ConvertFileSystemException {
		File projectPropertiesFile = new File(dir, "project.prp");
		if (!projectPropertiesFile.isFile()) {
			throw new ConvertFileSystemException(
				"Invalid project directory specified (project.prp not found): " + dir);
		}
		File dataDir = new File(dir, "data");
		if (!dataDir.isDirectory()) {
			dataDir = new File(dir, "idata"); // allow index upgrade
		}
		if (!dataDir.isDirectory()) {
			throw new ConvertFileSystemException(
				"Invalid project directory specified (project data not found): " + dir);
		}

		convertProjectDir(dataDir, "data", msgListener);

		File versionedDir = new File(dir, "versioned");
		if (versionedDir.isDirectory()) {
			convertProjectDir(versionedDir, "versioned data", msgListener);
		}

		File userDir = new File(dir, "user");
		if (userDir.isDirectory()) {
			convertProjectDir(userDir, "user data", msgListener);
		}
	}

}

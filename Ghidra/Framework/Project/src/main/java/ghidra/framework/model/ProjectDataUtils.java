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
package ghidra.framework.model;

import java.io.IOException;
import java.util.*;

import ghidra.util.InvalidNameException;

public class ProjectDataUtils {
	/**
	 * A not-thread-safe {@link DomainFile} iterator that recursively walks a
	 * {@link ProjectData project's data} and returns each {@code DomainFile} that is
	 * found.
	 */
	public static class DomainFileIterator implements Iterator<DomainFile> {

		private Deque<DomainFile> fileQueue = new LinkedList<>();
		private Deque<DomainFolder> folderQueue = new LinkedList<>();

		/**
		 * Recursively traverse a {@link Project} starting in its root folder.
		 *
		 * @param project
		 */
		public DomainFileIterator(Project project) {
			this(project.getProjectData().getRootFolder());
		}

		/**
		 * Recursively traverse the {@link DomainFile}s under a specific {@link DomainFolder}.
		 *
		 * @param startFolder
		 */
		public DomainFileIterator(DomainFolder startFolder) {
			folderQueue.add(startFolder);
		}

		private void queueNextFiles() {
			DomainFolder folder;
			while (fileQueue.isEmpty() && (folder = folderQueue.poll()) != null) {
				DomainFolder[] folders = folder.getFolders();
				for (int i = folders.length - 1; i >= 0; i--) {
					DomainFolder subfolder = folders[i];
					folderQueue.addFirst(subfolder);
				}
				for (DomainFile subfile : folder.getFiles()) {
					fileQueue.addLast(subfile);
				}
			}
		}

		@Override
		public boolean hasNext() {
			queueNextFiles();
			return !fileQueue.isEmpty();
		}

		@Override
		public DomainFile next() {
			return fileQueue.poll();
		}
	}

	/**
	 * A not-thread-safe {@link DomainFolder} iterator that recursively walks a
	 * {@link ProjectData project's data} and returns each {@code DomainFolder} that is
	 * found.
	 */
	public static class DomainFolderIterator implements Iterator<DomainFolder> {

		private Deque<DomainFolder> folderQueue = new LinkedList<>();
		private DomainFolder nextFolder;

		/**
		 * Recursively traverse a {@link Project} starting in its root folder.
		 *
		 * @param project
		 */
		public DomainFolderIterator(Project project) {
			this(project.getProjectData().getRootFolder());
		}

		/**
		 * Recursively traverse the {@link DomainFolder}s under a specific {@link DomainFolder}.
		 *
		 * @param startFolder
		 */
		public DomainFolderIterator(DomainFolder startFolder) {
			folderQueue.add(startFolder);
		}

		private void queueNextFiles() {
			if (nextFolder == null && !folderQueue.isEmpty()) {
				nextFolder = folderQueue.poll();
				DomainFolder[] folders = nextFolder.getFolders();
				for (int i = folders.length - 1; i >= 0; i--) {
					DomainFolder subfolder = folders[i];
					folderQueue.addFirst(subfolder);
				}
			}
		}

		@Override
		public boolean hasNext() {
			queueNextFiles();
			return nextFolder != null;
		}

		@Override
		public DomainFolder next() {
			DomainFolder tmp = nextFolder;
			nextFolder = null;
			return tmp;
		}
	}

	/**
	 * Returns a {@link Iterable} sequence of all the {@link DomainFile}s that exist under
	 * the specified {@link DomainFolder folder}.
	 *
	 * @param folder
	 * @return
	 */
	public static Iterable<DomainFile> descendantFiles(DomainFolder folder) {
		return () -> new DomainFileIterator(folder);
	}

	/**
	 * Returns a {@link Iterable} sequence of all the {@link DomainFolder}s that exist under
	 * the specified {@link DomainFolder folder}.
	 * @param folder
	 * @return
	 */
	public static Iterable<DomainFolder> descendantFolders(DomainFolder folder) {
		return () -> new DomainFolderIterator(folder);
	}

	/**
	 * Returns a Ghidra {@link DomainFolder} with the matching path, creating
	 * any missing parent folders as needed.
	 * <p>
	 * @param currentFolder starting {@link DomainFolder}.
	 * @param path relative path to the desired DomainFolder, using forward slashes
	 * as separators.  Empty string ok, multiple slashes in a row treated as single slash,
	 * trailing slashes ignored.
	 * @return {@link DomainFolder} that the path points to.
	 * @throws InvalidNameException if bad name
	 * @throws IOException if problem when creating folder
	 */
	public static DomainFolder createDomainFolderPath(DomainFolder currentFolder, String path)
			throws InvalidNameException, IOException {

		String[] pathElements = path.split("/");
		for (String pathElement : pathElements) {
			pathElement = pathElement.trim();
			if (pathElement.isEmpty()) {
				continue;
			}
			DomainFolder nextFolder = currentFolder.getFolder(pathElement);
			if (nextFolder == null) {
				// TODO: race condition between getFolder() and createFolder()
				nextFolder = currentFolder.createFolder(pathElement);
			}
			currentFolder = nextFolder;
		}
		return currentFolder;
	}

	/**
	 * Returns a Ghidra {@link DomainFolder} with the matching path, or null if not found.
	 * <p>
	 * @param currentFolder starting {@link DomainFolder}.
	 * @param path relative path to the desired DomainFolder, using forward slashes
	 * as separators.  Empty string ok, multiple slashes in a row treated as single slash,
	 * trailing slashes ignored.
	 * @return {@link DomainFolder} that the path points to or null if not found.
	 */
	public static DomainFolder lookupDomainPath(DomainFolder currentFolder, String path) {

		String[] pathElements = path.split("/");
		for (String pathElement : pathElements) {
			pathElement = pathElement.trim();
			if (pathElement.isEmpty()) {
				continue;
			}
			currentFolder = currentFolder.getFolder(pathElement);
			if (currentFolder == null) {
				break;
			}
		}
		return currentFolder;
	}

	/**
	 * Returns a unique name in a Ghidra {@link DomainFolder}.
	 *
	 * @param folder {@link DomainFolder} to check for child name collisions.
	 * @param baseName String base name of the file or folder
	 * @return "baseName" if no collisions, or "baseNameNNN" (where NNN is an incrementing
	 * integer value) when collisions are found, or null if there are more than 1000 collisions.
	 */
	public static String getUniqueName(DomainFolder folder, String baseName) {
		int tryNum = 0;
		int MAX_TRY_COUNT = 1000;
		while (tryNum < MAX_TRY_COUNT) {
			String tryName = baseName + (tryNum > 0 ? Integer.toString(tryNum) : "");
			if (folder.getFile(tryName) != null || folder.getFolder(tryName) != null) {
				tryNum++;
				continue;
			}
			return tryName;
		}
		return null;
	}
}

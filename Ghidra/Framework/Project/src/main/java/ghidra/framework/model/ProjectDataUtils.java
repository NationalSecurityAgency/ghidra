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
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.data.LinkHandler;
import ghidra.framework.data.LinkHandler.LinkStatus;
import ghidra.framework.data.LinkedGhidraFolder;
import ghidra.framework.store.FileSystem;
import ghidra.util.*;

public class ProjectDataUtils {

	/**
	 * Returns a {@link Iterable} of {@link DomainFile}s that exist under
	 * the specified {@link DomainFolder folder} including all sub-folder content.
	 * All folder-links and file-links will be ignored and files of all content-types will
	 * be returned by the iterator.
	 * <P>
	 * Use {@link ProjectDataUtils#descendantFiles(DomainFolder, DomainFileFilter)} for 
	 * finer-grained control over returned files.
	 *
	 * @param folder domain folder
	 * @return domain file iterator
	 */
	public static Iterable<DomainFile> descendantFiles(DomainFolder folder) {
		return new DomainFileIterator(folder, DomainFileFilter.NON_LINKED_FILE_FILTER);
	}

	/**
	 * Returns a {@link Iterable} of {@link DomainFile}s that exist under
	 * the specified {@link DomainFolder folder}, including all sub-folder content,
	 * which satisfy the specified filter restrictions.
	 * <P>
	 * NOTE: Care must be taken in the presence of folder-links and file-links since such links can
	 * result in the same files being returned by the iterator multiple times.  In
	 * general it is recommended that all links (see {@link DomainFile#isLink()}) be ignored
	 * when iterating over an entire project.  When restricting content-type it is highly recommended
	 * that the method {@link DomainFile#getDomainObjectClass()} since both linked and non-linked
	 * files for the same content will specify the same {@link DomainObject} class 
	 * (e.g., {@code Program.class}).
	 *
	 * @param folder domain folder
	 * @param filter the filter which determines which files should be returned by the
	 * iterator and what links should be followed.
	 * @return domain file iterator
	 */
	public static Iterable<DomainFile> descendantFiles(DomainFolder folder,
			DomainFileFilter filter) {
		return new DomainFileIterator(folder, filter);
	}

	/**
	 * Returns a {@link Iterable} of {@link DomainFolder}s that exist under
	 * the specified {@link DomainFolder folder} including all sub-folders.
	 * All folder-links will be ignored.
	 * <P>
	 * Use {@link ProjectDataUtils#descendantFolders(DomainFolder, boolean, boolean)} if 
	 * folder-links should be followed.
	 * 
	 * @param folder domain folder
	 * @return domain folder iterator
	 */
	public static Iterable<DomainFolder> descendantFolders(DomainFolder folder) {
		return descendantFolders(folder, true, true);
	}

	/**
	 * Returns a {@link Iterable} of {@link DomainFolder}s that exist under
	 * the specified {@link DomainFolder folder} including all sub-folders.
	 * subject to the specified folder-link restrictions.  All broken folder-links encountered
	 * will be logged and skipped.
	 *
	 * @param folder domain folder
	 * @param ignoreFolderLinks true if all folder-links should be ignored
	 * @param ignoreExternalLinks true if all external-links should be ignored 
	 *        (ignored if ignoreFolderLinks is true)
	 * @return domain folder iterator
	 */
	public static Iterable<DomainFolder> descendantFolders(DomainFolder folder,
			boolean ignoreFolderLinks, boolean ignoreExternalLinks) {
		return new DomainFolderIterator(folder, ignoreFolderLinks, ignoreExternalLinks);
	}

	/**
	 * Returns a Ghidra {@link DomainFolder} with the matching path, creating
	 * any missing parent folders as needed.  Broken folder-links will always be ignored.
	 * 
	 * @param currentFolder starting {@link DomainFolder}.
	 * @param path relative path to the desired DomainFolder, using forward slashes
	 * as separators.  Empty string ok, multiple slashes in a row treated as single slash,
	 * trailing slashes ignored.
	 * @return {@link DomainFolder} that the path points to.
	 * @throws InvalidNameException if bad name
	 * @throws ReadOnlyException if unable to create a folder within a read-only project
	 * @throws IOException if problem when creating folder or a conflicting/broken folder/folder-link
	 * encountered.
	 */
	public static DomainFolder createDomainFolderPath(DomainFolder currentFolder, String path)
			throws InvalidNameException, IOException {

		if (!currentFolder.isInWritableProject()) {
			throw new ReadOnlyException("Folder is read-only: " + currentFolder);
		}

		if (StringUtils.isBlank(path)) {
			return currentFolder;
		}

		DomainFolder folder = currentFolder;

		String[] pathElements = path.split(FileSystem.SEPARATOR);
		for (String pathElement : pathElements) {

			// pathElement = pathElement.trim(); // NOTE: Seems too forgiving
			if (pathElement.isEmpty()) {
				continue;
			}

			DomainFolder subFolder = folder.getFolder(pathElement);

			// Check for folder link-file
			DomainFile file = folder.getFile(pathElement);
			if (file != null && file.isLink()) {
				LinkFileInfo linkInfo = file.getLinkInfo();
				if (linkInfo.isFolderLink()) {
					if (subFolder != null) {
						throw new IOException(
							"Folder and folder-link name conflict encountered: " + file);
					}
					// May only follow non-external and non-broken folder-links
					if (linkInfo.isExternalLink()) {
						throw new IOException("May not follow external folder-link: " + file);
					}
					if (LinkHandler.getLinkFileStatus(file, null) == LinkStatus.BROKEN) {
						throw new IOException("May not follow broken folder-link: " + file);
					}
					subFolder = linkInfo.getLinkedFolder();
				}
			}
			if (subFolder == null) {
				subFolder = folder.createFolder(pathElement);
			}
			folder = subFolder;
		}

		return folder;
	}

	/**
	 * Returns a Ghidra {@link DomainFolder} with the matching path within the baseFolder's
	 * project, or null if not found. Broken and external folder-links will be ignored.
	 * 
	 * @param baseFolder Base {@link DomainFolder} for relativePath 
	 * @param relativePath path relative to the specified DomainFolder, using forward slashes
	 * as separators.  Empty string ok, multiple slashes in a row treated as single slash,
	 * leading and trailing slashes ignored.
	 * @return {@link DomainFolder} that the path points to or null if not found.
	 */
	public static DomainFolder getDomainFolder(DomainFolder baseFolder, String relativePath) {
		return getDomainFolder(baseFolder, relativePath,
			DomainFolderFilter.ALL_INTERNAL_FOLDERS_FILTER);
	}

	/**
	 * Returns a Ghidra {@link DomainFolder} with the matching path, or null if not found.
	 * 
	 * @param baseFolder Base {@link DomainFolder} for relativePath 
	 * @param relativePath path relative to the specified DomainFolder, using forward slashes
	 * as separators.  Empty string ok, multiple slashes in a row treated as single slash,
	 * leading and trailing slashes ignored.
	 * @param filter domain folder filter which constrains returned folder and following of 
	 * folder-links. Broken links will always be ignored.
	 * @return {@link DomainFolder} that the path points to or null if not found or path contains
	 * a broken folder-link.
	 */
	public static DomainFolder getDomainFolder(DomainFolder baseFolder, String relativePath,
			DomainFolderFilter filter) {

		if (StringUtils.isBlank(relativePath)) {
			return baseFolder;
		}

		DomainFolder folder = baseFolder;

		String[] pathElements = relativePath.split(FileSystem.SEPARATOR);
		for (String pathElement : pathElements) {

			// pathElement = pathElement.trim(); // NOTE: Seems too forgiving
			if (pathElement.isEmpty()) {
				continue;
			}

			DomainFolder subFolder = folder.getFolder(pathElement);

			// Check for folder link-file
			// NOTE: if real folder name matches folder-link-file name it will fail
			// to resolve folder - either folder or link should be renamed.
			DomainFile file = folder.getFile(pathElement);
			if (file != null && file.isLink()) {
				LinkFileInfo linkInfo = file.getLinkInfo();
				if (linkInfo.isFolderLink()) {
					if (filter.ignoreFolderLinks()) {
						return null;
					}
					if (subFolder != null) {
						Msg.error(ProjectDataUtils.class,
							"Folder and folder-link name conflict encountered: " + file);
						return null; // conflicting folder and folder-link
					}
					if (linkInfo.isExternalLink() && filter.ignoreExternalLinks()) {
						return null;
					}
					if (LinkHandler.getLinkFileStatus(file, null) == LinkStatus.BROKEN) {
						Msg.warn(ProjectDataUtils.class,
							"Skipping broken folder-link: " + file.getPathname());
						return null;
					}
					subFolder = linkInfo.getLinkedFolder();
				}
			}

			if (subFolder == null) {
				return null; // folder path element not found
			}
			folder = subFolder;
		}

		return folder;
	}

	/**
	 * Returns a unique folder/file name within the specified {@link DomainFolder folder}.
	 * The specified {@code baseName} will be used as the basis for the name returned with an 
	 * appended number.
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

	/**
	 * A non-thread-safe {@link DomainFile} iterator that recursively walks a
	 * {@link ProjectData project's data} and returns each {@code DomainFile} that is
	 * found.
	 * <P>
	 * This iterator will never return a folder-link as a file.  If a folder-link is not ignored
	 * its children will be processed.
	 */
	private static class DomainFileIterator implements Iterator<DomainFile>, Iterable<DomainFile> {

		private Deque<DomainFile> fileQueue = new LinkedList<>();
		private Deque<DomainFolder> folderQueue = new LinkedList<>();

		private DomainFileFilter filter;

		/**
		 * Recursively traverse the {@link DomainFile}s under a specific {@link DomainFolder}.
		 * <P>
		 * NOTE: Care must be taken in the presence of folder-links and file-links since such links
		 * can result in the same files being returned by the iterator multiple times.  In
		 * general it is recommended that all links (see {@link DomainFile#isLink()}) be ignored
		 * when iterating over an entire project.  When restricting content-type it is highly recommended
		 * that the method {@link DomainFile#getDomainObjectClass()} since both linked and non-linked
		 * files for the same content will specify the same {@link DomainObject} class 
		 * (e.g., {@code Program.class}).
		 * 
		 * @param startFolder folder to start from
		 * @param filter the filter which determines which files should be returned by the
		 * iterator and what links should be followed.  Following of external links is blocked
		 * and takes precendence over specified filter.
		 */
		DomainFileIterator(DomainFolder startFolder, DomainFileFilter filter) {
			Objects.requireNonNull(startFolder, "folder not specified");
			Objects.requireNonNull(filter, "domain file filter not specified");
			folderQueue.add(startFolder);
			this.filter = filter;
		}

		private void queueNextFiles() {
			DomainFolder folder;
			while (fileQueue.isEmpty() && (folder = folderQueue.poll()) != null) {
				DomainFolder[] folders = folder.getFolders();
				for (int i = folders.length - 1; i >= 0; i--) {
					DomainFolder subfolder = folders[i];
					folderQueue.addFirst(subfolder);
				}
				for (DomainFile df : folder.getFiles()) {
					if (df.isLink()) {
						AtomicReference<LinkStatus> linkStatus = new AtomicReference<>();
						if (skipLinkFile(df, linkStatus)) {
							continue;
						}
						if (df.getLinkInfo().isFolderLink()) {
							LinkedGhidraFolder linkedFolder =
								resolveFolderLink(df, linkStatus.get());
							if (linkedFolder != null) {
								// queue folder for subsequent processing
								folderQueue.addFirst(linkedFolder);
							}
							continue;
						}
						// A file-link may drop-through (e.g., ProgramLink) but will be
						// subject to filter.accept method below.
					}
					if (filter.accept(df)) {
						fileQueue.addLast(df);
					}
				}
			}
		}

		private LinkedGhidraFolder resolveFolderLink(DomainFile folderLinkFile, LinkStatus status) {
			if (status == LinkStatus.BROKEN) {
				Msg.warn(this, "Skipping broken folder-link: " + folderLinkFile.getPathname());
				return null;
			}
			if (status == LinkStatus.EXTERNAL && !filter.followExternallyLinkedFolders()) {
				return null;
			}
			return folderLinkFile.getLinkInfo().getLinkedFolder();
		}

		/**
		 * Check linkFile against filter to see if it should be skipped.
		 * @param linkFile link file to be checked
		 * @param returnedLinkStatus if method returns false this will be updated with status
		 * @return true if linkFile should be skipped, else false
		 */
		private boolean skipLinkFile(DomainFile linkFile,
				AtomicReference<LinkStatus> returnedLinkStatus) {
			LinkFileInfo linkInfo = linkFile.getLinkInfo();
			boolean isFolderLink = linkInfo.isFolderLink();
			if (isFolderLink && filter.ignoreFolderLinks()) {
				return true;
			}
			LinkStatus linkStatus = LinkHandler.getLinkFileStatus(linkFile, null);
			if (linkStatus == LinkStatus.BROKEN && filter.ignoreBrokenLinks()) {
				return true;
			}
			if (linkStatus == LinkStatus.EXTERNAL) {
				return true;
			}
			if (linkStatus == LinkStatus.BROKEN) {
				// Filter did not ignore broken link so we will simply report it and continue
				Msg.warn(this, "Skipping broken link-file: " + linkFile.getPathname());
				return true;
			}
			returnedLinkStatus.set(linkStatus);
			return false;
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

		@Override
		public Iterator<DomainFile> iterator() {
			return this;
		}
	}

	/**
	 * A non-thread-safe {@link DomainFolder} iterator that recursively walks a
	 * {@link ProjectData project's data} and returns each {@code DomainFolder} that is
	 * found.  Non-broken folder-links will be followed based upon specified constraints.
	 */
	private static class DomainFolderIterator
			implements Iterator<DomainFolder>, Iterable<DomainFolder> {

		private Deque<DomainFolder> folderQueue = new LinkedList<>();
		private DomainFolder nextFolder;

		private boolean ignoreFolderLinks;
		private boolean ignoreExternalLinks;

		/**
		 * Recursively traverse the {@link DomainFolder}s under a specific {@link DomainFolder}
		 * subject to the specified folder-link restrictions.  All broken folder-links encountered
		 * will be logged and skipped.
		 *
		 * @param startFolder domain folder
		 * @param ignoreFolderLinks true if all folder-links should be ignored
		 * @param ignoreExternalLinks true if all external-links should be ignored 
		 *        (ignored if ignoreFolderLinks is true)
		 */
		DomainFolderIterator(DomainFolder startFolder, boolean ignoreFolderLinks,
				boolean ignoreExternalLinks) {
			folderQueue.add(startFolder);
			this.ignoreFolderLinks = ignoreFolderLinks;
			this.ignoreExternalLinks = ignoreExternalLinks;
		}

		private void queueNextFiles() {
			if (nextFolder == null && !folderQueue.isEmpty()) {
				nextFolder = folderQueue.poll();
				DomainFolder[] folders = nextFolder.getFolders();
				for (int i = folders.length - 1; i >= 0; i--) {
					DomainFolder subfolder = folders[i];
					folderQueue.addFirst(subfolder);
				}
				if (!ignoreFolderLinks) {
					for (DomainFile df : nextFolder.getFiles()) {
						LinkedGhidraFolder linkedFolder = resolveFolderLink(df);
						if (linkedFolder != null) {
							// queue folder for subsequent processing
							folderQueue.addFirst(linkedFolder);
						}
					}
				}
			}

		}

		private LinkedGhidraFolder resolveFolderLink(DomainFile file) {
			LinkFileInfo linkInfo = file.getLinkInfo();
			if (linkInfo == null || !linkInfo.isFolderLink()) {
				return null;
			}
			LinkStatus linkStatus = LinkHandler.getLinkFileStatus(file, null);
			if (linkStatus == LinkStatus.BROKEN) {
				Msg.warn(this, "Skipping broken folder-link: " + file.getPathname());
				return null;
			}
			if (linkStatus == LinkStatus.EXTERNAL && ignoreExternalLinks) {
				return null;
			}
			return linkInfo.getLinkedFolder();
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

		@Override
		public Iterator<DomainFolder> iterator() {
			return this;
		}
	}
}

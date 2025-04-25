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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import javax.swing.Icon;

import org.apache.commons.lang3.StringUtils;

import generic.theme.GIcon;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.*;
import ghidra.framework.protocol.ghidra.GhidraURLQuery.LinkFileControl;
import ghidra.framework.store.*;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import utility.function.Dummy;

/**
 * NOTE:  ALL ContentHandler implementations MUST END IN "ContentHandler".  If not,
 * the ClassSearcher will not find them.
 * 
 * <code>LinkHandler</code> defines an application interface for handling domain files which are
 * shortcut links to another supported content type.
 * 
 * @param <T> {@link URLLinkObject} implementation class
 */
public abstract class LinkHandler<T extends DomainObjectAdapterDB> implements ContentHandler<T> {

	/**
	 * Legacy linkPath metadata key for database storage
	 */
	public static final String URL_METADATA_KEY = "link.url";

	/**
	 * 16x16 link icon where link is placed in lower-left corner
	 */
	public static final Icon LINK_ICON = new GIcon("icon.content.handler.link.overlay");

	/**
	 * {@link LinkStatus} provides a link evaluation for its ulimate type or if it is
	 * considered broken.  See {@link LinkHandler#getLinkFileStatus(DomainFile, Consumer)}.
	 */
	public enum LinkStatus {

		/**
		 * The link-file specified does not refer to a valid file or content-type.
		 */
		BROKEN,

		/**
		 * The link-file ultimately refers to a file or folder path within the same project.
		 */
		INTERNAL,

		/**
		 * The link-file ultimately refers to an external project/repository path with a Ghidra URL.
		 */
		EXTERNAL,

		/**
		 * The specified file is not a link-file
		 */
		NON_LINK;
	}

	@Override
	public LinkHandler<?> getLinkHandler() {
		return this; // allow links to the same type of link
	}

	/**
	 * Create a link file using the specified URL
	 * @param linkPath link path or Ghidra URL.
	 * @param fs filesystem where link file should be created 
	 * @param folderPath folder path which should contain link file
	 * @param linkFilename link filename
	 * @throws IOException if an IO error occurs
	 * @throws InvalidNameException if invalid folderPath or linkFilename specified
	 */
	protected final void createLink(String linkPath, LocalFileSystem fs, String folderPath,
			String linkFilename) throws IOException, InvalidNameException {

		fs.createTextDataItem(folderPath, linkFilename, FileIDFactory.createFileID(),
			getContentType(), linkPath, null);
	}

	@Override
	public final long createFile(FileSystem fs, FileSystem userfs, String path, String name,
			DomainObject domainObject, TaskMonitor monitor)
			throws IOException, InvalidNameException, CancelledException {
		throw new UnsupportedOperationException("createLink must be used for link-file");
	}

	@Override
	public final T getDomainObject(FolderItem item, FileSystem userfs, long checkoutId,
			boolean okToUpgrade, boolean okToRecover, Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException {
		throw new UnsupportedOperationException("getObject must be used for link-file");
	}

	@Override
	public final T getReadOnlyObject(FolderItem item, int version, boolean okToUpgrade,
			Object consumer, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		throw new UnsupportedOperationException("getObject must be used for link-file");
	}

	@Override
	public T getImmutableObject(FolderItem item, Object consumer, int version, int minChangeVersion,
			TaskMonitor monitor) throws IOException, CancelledException, VersionException {
		throw new UnsupportedOperationException("getObject must be used for link-file");
	}

	/**
	 * Get immutable or read-only  domain object based upon an initial external GhidraURL.
	 * @param ghidraUrl external URL
	 * @param version {@link DomainFile} version (ignored if URL end-point is a DomainFile since 
	 * the {@link GhidraURLConnection} has no way to convey the version.
	 * @param consumer domain object consumer
	 * @param monitor task monitor
	 * @param immutable true if object is open immutable (no upgrade support), else read-only
	 * @return domain object
	 * @throws IOException if an IO error occurs
	 * @throws VersionException if a version exception prevents opening the file
	 * @throws CancelledException if task is cancelled
	 */
	T getObject(URL ghidraUrl, int version, Object consumer, TaskMonitor monitor, boolean immutable)
			throws IOException, VersionException, CancelledException {

		// TODO: may not have insight into version associated with a link-file

		Class<?> domainObjectClass = getDomainObjectClass();
		if (domainObjectClass == null) {
			throw new UnsupportedOperationException("");
		}

		AtomicReference<VersionException> verExcRef = new AtomicReference<>();
		AtomicReference<T> domainObjectRef = new AtomicReference<>();
		GhidraURLQuery.queryUrl(ghidraUrl, getDomainObjectClass(),
			new GhidraURLResultHandlerAdapter(true) {
				// GhidraURLQuery will perform the link-following
				@Override
				public void processResult(DomainFile domainFile, URL url, TaskMonitor m)
						throws IOException, CancelledException {
					if (!getDomainObjectClass()
							.isAssignableFrom(domainFile.getDomainObjectClass())) {
						throw new BadLinkException("Expected " + getDomainObjectClass() +
							" but linked to " + domainFile.getDomainObjectClass());
					}
					try {
						@SuppressWarnings("unchecked")
						T linkedObject = immutable
								? (T) domainFile.getImmutableDomainObject(consumer, version,
									monitor)
								: (T) domainFile.getReadOnlyDomainObject(consumer, version,
									monitor);
						domainObjectRef.set(linkedObject);
					}
					catch (VersionException e) {
						verExcRef.set(e);
					}
				}

				@Override
				public void handleUnauthorizedAccess(URL url) throws IOException {
					throw new IOException("Authorization failure");
				}
			}, LinkFileControl.FOLLOW_EXTERNAL, monitor);

		VersionException versionException = verExcRef.get();
		if (versionException != null) {
			throw versionException;
		}

		T domainObj = domainObjectRef.get();
		if (domainObj == null) {
			throw new IOException(
				"Failed to obtain linked object for unknown reason: " + ghidraUrl);
		}
		return domainObj;
	}

	@Override
	public final ChangeSet getChangeSet(FolderItem versionedFolderItem, int olderVersion,
			int newerVersion) throws VersionException, IOException {
		return null;
	}

	@Override
	public final DomainObjectMergeManager getMergeManager(DomainObject resultsObj,
			DomainObject sourceObj, DomainObject originalObj, DomainObject latestObj) {
		return null;
	}

	@Override
	public final boolean isPrivateContentType() {
		throw new UnsupportedOperationException("Link file requires checking server vs local URL");
	}

	/**
	 * Get the base icon for this link-file which does not include the 
	 * link overlay icon.
	 */
	@Override
	abstract public Icon getIcon();

	//////////////////////////
	// Static package methods
	//////////////////////////

	/**
	 * Determine if the contents of a link file can be shared (i.e., added to repository).
	 * Local project Ghidra-URL paths may not be shared.
	 * 
	 * @param linkFile link file
	 * @return true if link may be shared
	 */
	static boolean canShareLink(FolderItem linkFile) {
		try {
			String linkPath = getLinkPath(linkFile);
			return !GhidraURL.isLocalGhidraURL(linkPath);
		}
		catch (IOException e) {
			// ignore
		}
		return false;
	}

	/**
	 * Get the stored link-path or Ghidra-URL
	 * 
	 * @param linkFile link file (see {@link DomainFile#isLink()}).
	 * @return stored link-path or Ghidra-URL
	 * @throws IOException if an IO error occurs or a valid link-file was not specified
	 */
	static String getLinkPath(FolderItem linkFile) throws IOException {
		String contentType = linkFile.getContentType();
		ContentHandler<?> ch = DomainObjectAdapter.getContentHandler(contentType);
		if (ch instanceof LinkHandler) {
			String linkPath = null;
			if (linkFile instanceof TextDataItem textItem) {
				linkPath = textItem.getTextData();
			}
			if (linkPath == null) {
				// Fallback to reading old database storage form as metadata
				Map<String, String> metadata = GhidraFileData.getMetadata(linkFile);
				linkPath = metadata.get(URL_METADATA_KEY);
			}
			if (StringUtils.isBlank(linkPath)) {
				throw new IOException("Invalid link-file: " + linkFile.getPathName());
			}
			return linkPath;
		}
		throw new IOException("Invalid link-file content: " + linkFile.getPathName());
	}

	//////////////////////////
	// Static public methods
	//////////////////////////

	/**
	 * Get the link URL which corresponds to the specified link file's link-path.
	 * If link-path was originally specified as an internal path it will be transformed 
	 * into a URL.  See {@link DomainFile#isLink()}.
	 * 
	 * @param linkFile link-file domain file which may correspond to a linked-folder or file.
	 * @return link URL or null if invalid link-URL or a non-link-file is specified
	 * @throws IOException if linkFile has an invalid relative link-path that failed to normalize
	 */
	public static URL getLinkURL(DomainFile linkFile) throws IOException {

		// TODO: link traversal not handled (e.g., path element is a linked folder)
		// May have to follow incrementally

		String linkPath = getAbsoluteLinkPath(linkFile);
		if (linkPath == null) {
			return null;
		}

		try {
			if (!GhidraURL.isGhidraURL(linkPath)) {
				ProjectData projectData = linkFile.getParent().getProjectData();
				return GhidraURL.makeURL(projectData.getProjectLocator(), linkPath, null);
			}
			return new URL(linkPath);
		}
		catch (MalformedURLException | IllegalArgumentException e) {
			// Bad URL from link path
			throw new IOException("Failed to form URL from linkPath: " + linkPath, e);
		}
	}

	/**
	 * Get the Ghidra URL or absolute normalized link-path from a link file.
	 * Path normalization eliminates any path element of "./" or "../".
	 * A local folder-link path will always end with a "/" path separator.
	 * Path normalization is not performed on Ghidra URLs.
	 * 
	 * @param linkFile link file
	 * @return Ghidra URL or absolute normalized link-path from a link file
	 * @throws IOException if linkFile has an invalid relative link-path that failed to normalize
	 */
	public static String getAbsoluteLinkPath(DomainFile linkFile) throws IOException {

		LinkFileInfo linkInfo = linkFile.getLinkInfo();
		if (linkInfo == null) {
			return null;
		}
		String linkPath = linkInfo.getLinkPath();
		if (StringUtils.isBlank(linkPath)) {
			return null;
		}

		String path = linkPath;
		if (!GhidraURL.isGhidraURL(path)) {
			if (!linkPath.startsWith(FileSystem.SEPARATOR)) {
				path = linkFile.getParent().getPathname();
				if (!path.endsWith(FileSystem.SEPARATOR)) {
					path += FileSystem.SEPARATOR;
				}
				path += linkPath;
			}
			try {
				return FileSystem.normalizePath(path);
			}
			catch (IllegalArgumentException e) {
				throw new IOException("Invalid link path: " + linkPath);
			}
		}
		return path;
	}

	/**
	 * Determine the link status for the specified {@link DomainFile#isLink() link-file}.
	 * If a status is {@link LinkStatus#BROKEN} and an {@code errorConsumer} has been specified 
	 * the error details will be reported.
	 * 
	 * @param file domain file
	 * @param errorConsumer broken link error consumer (may be null)
	 * @return link status
	 */
	public static LinkStatus getLinkFileStatus(DomainFile file, Consumer<String> errorConsumer) {
		AtomicReference<LinkStatus> status = new AtomicReference<>();
		followInternalLinkage(file, s -> status.set(s), errorConsumer);
		return status.get();
	}

	/**
	 * Add real internal folder path for specified folder or folder-link and check for 
	 * circular conflict.
	 * @param pathSet real path accumulator
	 * @param linkPath internal linkPath
	 * @return true if no path conflict detected, false if path conflict is detected
	 */
	private static boolean addLinkPathPath(Set<String> pathSet, String linkPath) {
		// Must ensure that all paths end with '/' separator - even if path is endpoint
		if (!linkPath.endsWith(FileSystem.SEPARATOR)) {
			linkPath += FileSystem.SEPARATOR;
		}
		for (String path : pathSet) {
			if (path.startsWith(linkPath)) {
				return false;
			}
		}
		pathSet.add(linkPath);
		return true;
	}

	/**
	 * Follow the internal linkage, if any, for the specified file.  Any broken linkage details will
	 * be reported to the specified {@code errorConsumer}. 
	 *  
	 * @param file domain file to be checked
	 * @param  statusConsumer link status consumer (required)
	 * @param errorConsumer broken link error consumer (may be null)
	 * @return the final {@link DomainFile} within the same project or null if file specified was 
	 * not a link-file.  A broken link will return the last valid link-file in chain.
	 */
	public static DomainFile followInternalLinkage(DomainFile file,
			Consumer<LinkStatus> statusConsumer, Consumer<String> errorConsumer) {

		Objects.requireNonNull(statusConsumer, "Status consumer is required");

		errorConsumer = Dummy.ifNull(errorConsumer);

		LinkFileInfo linkInfo = file.getLinkInfo();
		if (linkInfo == null) {
			statusConsumer.accept(LinkStatus.NON_LINK);
			return null;
		}

		Set<String> linkPathsVisited = new HashSet<>();

		ProjectData projectData;
		DomainFolder parent = file.getParent();
		if (parent instanceof LinkedDomainFolder lf) {
			try {
				projectData = lf.getLinkedProjectData();
				addLinkPathPath(linkPathsVisited, lf.getLinkedPathname());
			}
			catch (IOException e) {
				throw new RuntimeException("Unexpected", e);
			}
		}
		else {
			projectData = parent.getProjectData();
			addLinkPathPath(linkPathsVisited, file.getPathname());
		}

		String contentType = file.getContentType();
		Class<? extends DomainObject> domainObjectClass = file.getDomainObjectClass();
		boolean isFolderLink =
			FolderLinkContentHandler.FOLDER_LINK_CONTENT_TYPE.equals(contentType);

		// Loop recurses through link-chain to arrive at final internal link-file
		DomainFile nextLinkFile = file;

		while (true) {

			String linkPath = null;
			try {
				linkPath = LinkHandler.getAbsoluteLinkPath(nextLinkFile);
			}
			catch (IOException e) {
				errorConsumer.accept(e.getMessage());
				break;
			}
			if (linkPath == null) {
				errorConsumer.accept("Invalid link-path storage");
				break;
			}

			if (isFolderLink) {
				String name = nextLinkFile.getName();
				if (nextLinkFile.getParent().getFolder(name) != null) {
					errorConsumer.accept(
						"Folder name conflicts with this folder-link in same folder: " + name);
					break;
				}
			}

			if (GhidraURL.isGhidraURL(linkPath)) {
				statusConsumer.accept(LinkStatus.EXTERNAL);
				return nextLinkFile;
			}

			if (!addLinkPathPath(linkPathsVisited, linkPath)) {
				errorConsumer.accept("Link has a circular reference");
				break; // broken and can't continue
			}

			DomainFile linkedFile = null;
			if (!linkPath.endsWith(FileSystem.SEPARATOR)) {
				linkedFile = projectData.getFile(linkPath);
			}

			if (isFolderLink) {
				// Check for folder existence at linkPath
				if (getNonLinkedFolder(projectData, linkPath) != null) {
					// Check for folder-link that conflicts with folder found
					if (linkedFile != null) {
						LinkFileInfo linkedFileLinkInfo = linkedFile.getLinkInfo();
						if (linkedFileLinkInfo != null && linkedFileLinkInfo.isFolderLink()) {
							errorConsumer.accept(
								"Referenced folder name conflicts with folder-link in the same folder: " +
									linkPath);
							break;
						}
					}
					statusConsumer.accept(LinkStatus.INTERNAL);
					return nextLinkFile;
				}
			}

			if (linkedFile == null) {
				String acceptableType = isFolderLink ? "folder" : "file";
				errorConsumer.accept(
					"Broken " + contentType + " - " + acceptableType + " not found: " + linkPath);
				break;
			}

			if (!domainObjectClass.isAssignableFrom(linkedFile.getDomainObjectClass())) {
				// NOTE: folder-links use NullFolderDomainObject
				errorConsumer.accept(
					"Broken " + contentType + " - incompatible content-type: " + linkPath);
				break;
			}

			if (!linkedFile.isLink()) {
				statusConsumer.accept(LinkStatus.INTERNAL);
				return linkedFile;
			}

			nextLinkFile = linkedFile;
		}

		// Must be broken to end up here
		statusConsumer.accept(LinkStatus.BROKEN);
		return nextLinkFile;
	}

	private static DomainFolder getNonLinkedFolder(ProjectData projectData, String path) {
		int len = path.length();
		if (len == 0 || path.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			throw new IllegalArgumentException(
				"Absolute path must begin with '" + FileSystem.SEPARATOR_CHAR + "'");
		}

		DomainFolder folder = projectData.getRootFolder();
		String[] split = path.split(FileSystem.SEPARATOR);
		if (split.length == 0) {
			return folder;
		}

		for (int i = 1; i < split.length; i++) {
			DomainFolder subFolder = folder.getFolder(split[i]);
			if (subFolder == null) {
				return null;
			}
			folder = subFolder;
		}
		return folder;
	}

}

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

import java.awt.*;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.Icon;

import org.apache.commons.lang3.StringUtils;

import db.DBHandle;
import db.Field;
import db.buffers.*;
import generic.theme.GColor;
import generic.theme.GIcon;
import ghidra.framework.client.*;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.store.*;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.framework.store.local.LocalFolderItem;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import resources.MultiIcon;
import resources.icons.TranslateIcon;

/**
 * {@link GhidraFileData} provides the managed object which represents a project file that 
 * corresponds to matched {@link FolderItem} pair across both a versioned and private 
 * filesystem and viewed as a single file at the project level.  This class closely mirrors the
 * {@link DomainFile} interface and is used by the {@link GhidraFile} implementation; both of which
 * represent immutable file references.  Changes made to this file's name or path are not reflected 
 * in old {@link DomainFile} instances and must be re-instantiated following such a change.  
 * Any long-term retention of {@link DomainFolder} and {@link DomainFile} instances requires an 
 * appropriate change listener to properly discard/reacquire such instances.
 */
public class GhidraFileData {

	static final int ICON_WIDTH = 18;
	static final int ICON_HEIGHT = 17;

	private static final boolean ALWAYS_MERGE = System.getProperty("ForceMerge") != null;

	//@formatter:off
	public static final Icon UNSUPPORTED_FILE_ICON = new GIcon("icon.project.data.file.ghidra.unsupported");
	public static final Icon CHECKED_OUT_ICON = new GIcon("icon.project.data.file.ghidra.checked.out");
	public static final Icon CHECKED_OUT_EXCLUSIVE_ICON = new GIcon("icon.project.data.file.ghidra.checked.out.exclusive");
	public static final Icon HIJACKED_ICON = new GIcon("icon.project.data.file.ghidra.hijacked");

	public static final Icon VERSION_ICON = new VersionIcon();
	public static final Icon READ_ONLY_ICON = new GIcon("icon.project.data.file.ghidra.read.only");
	public static final Icon NOT_LATEST_CHECKED_OUT_ICON = new GIcon("icon.project.data.file.ghidra.not.latest");
	//@formatter:on

	private DefaultProjectData projectData;
	private LocalFileSystem fileSystem;
	private FileSystem versionedFileSystem;
	private DomainFolderChangeListener listener;

	private GhidraFolderData parent;
	private String name;
	private String fileID;

	private LocalFolderItem folderItem;
	private FolderItem versionedFolderItem;

	private Icon icon;
	private Icon disabledIcon;

	private AtomicBoolean busy = new AtomicBoolean();

// TODO: Many of the old methods assumed that the state was up-to-date due to
// refreshing ... we are relying on non-refreshed data to be dropped from cache map and no
// longer used.

	/**
	 * Construct a file instance with a specified name and a correpsonding parent folder
	 * @param parent parent folder
	 * @param name file name
	 * @throws IOException if an IO error occurs
	 */
	GhidraFileData(GhidraFolderData parent, String name) throws IOException {

		this.parent = parent;
		this.name = name;

		this.projectData = parent.getProjectData();
		this.fileSystem = parent.getLocalFileSystem();
		this.versionedFileSystem = parent.getVersionedFileSystem();
		this.listener = parent.getChangeListener();

		refresh();
	}

	/**
	 * Construct a new file instance with a specified name and a corresponding parent folder using
	 * up-to-date folder items.
	 * @param parent parent folder
	 * @param name file name
	 * @param folderItem local folder item
	 * @param versionedFolderItem versioned folder item
	 */
	GhidraFileData(GhidraFolderData parent, String name, LocalFolderItem folderItem,
			FolderItem versionedFolderItem) {
		this.parent = parent;
		this.name = name;
		this.folderItem = folderItem;
		this.versionedFolderItem = versionedFolderItem;

		this.projectData = parent.getProjectData();
		this.fileSystem = parent.getLocalFileSystem();
		this.versionedFileSystem = parent.getVersionedFileSystem();
		this.listener = parent.getChangeListener();

		validateCheckout();
		updateFileID();
	}

	void refresh(LocalFolderItem localFolderItem, FolderItem verFolderItem) {
		icon = null;
		disabledIcon = null;

		this.folderItem = localFolderItem;
		this.versionedFolderItem = verFolderItem;

		validateCheckout();
		boolean fileIDset = updateFileID();

		if (parent.visited()) {
			// NOTE: we should maintain some cached data so we can determine if something really changed
			listener.domainFileStatusChanged(getDomainFile(), fileIDset);
		}
	}

	private boolean refresh() throws IOException {
		String parentPath = parent.getPathname();
		if (folderItem == null) {
			folderItem = fileSystem.getItem(parentPath, name);
		}
		else {
			folderItem = folderItem.refresh();
		}
		if (versionedFileSystem.isOnline()) {
			try {
				if (versionedFolderItem == null) {
					versionedFolderItem = versionedFileSystem.getItem(parentPath, name);
				}
				else {
					versionedFolderItem = versionedFolderItem.refresh();
				}
				validateCheckout();
			}
			catch (IOException e) {
				// ignore
			}
		}
		if (folderItem == null && versionedFolderItem == null) {
			throw new FileNotFoundException(name + " not found");
		}
		return updateFileID();
	}

	private boolean updateFileID() {
		boolean fileIdWasNull = fileID == null;
		fileID = folderItem != null ? folderItem.getFileID() : versionedFolderItem.getFileID();
		return fileIdWasNull && fileID != null;
	}

	/**
	 * Notification callback that this file's status may have changed
	 * @throws IOException if IO error occurs
	 */
	void statusChanged() throws IOException {
		statusChanged(false);
	}

	private void statusChanged(boolean fileIDset) throws IOException {
		icon = null;
		disabledIcon = null;
		fileIDset |= refresh();
		if (parent.visited()) {
			// NOTE: we should maintain some cached data so we can determine if something really changed
			listener.domainFileStatusChanged(getDomainFile(), fileIDset);
		}
	}

	private void validateCheckout() {
		if (fileSystem.isReadOnly() || !versionedFileSystem.isOnline()) {
			return;
		}
		try {
			if (folderItem != null && folderItem.isCheckedOut()) {
				// Cleanup checkout status which may be stale
				if (versionedFolderItem != null) {
					ItemCheckoutStatus coStatus =
						versionedFolderItem.getCheckout(folderItem.getCheckoutId());
					if (coStatus == null) {
						folderItem.clearCheckout();
					}
				}
				else {
					folderItem.clearCheckout();
				}
			}
		}
		catch (IOException e) {
			// ignore
		}
	}

	/**
	 * Perform file in-use / busy check
	 * @throws FileInUseException if file is in-use or busy
	 */
	void checkInUse() throws FileInUseException {
		synchronized (fileSystem) {
			if (busy.get() || getOpenedDomainObject() != null) {
				throw new FileInUseException(name + " is in use");
			}
		}
	}

	/**
	 * Returns true if the domain object in this domain file exists and has an open transaction.
	 * @return true if busy
	 */
	boolean isBusy() {
		if (busy.get()) {
			return true;
		}
		DomainObjectAdapter dobj = getOpenedDomainObject();
		return dobj != null && !dobj.canLock();
	}

	/**
	 * Removes this file from file-index maintained by {@link ProjectData} instance
	 * following its removal from the project.
	 */
	void dispose() {
		projectData.removeFromIndex(fileID);
// NOTE: clearing the following can cause issues since there may be some residual
// activity/use which will get a NPE
//		parent = null;
//		projectData = null;
//		listener = null;
	}

	/**
	 * Returns a unique file-ID if one has been established or null
	 * @return the file-ID or null if failed to obtain ID
	 */
	String getFileID() {
		return fileID;
	}

	/**
	 * Returns the path name to the domain object.
	 * @return the path name
	 */
	String getPathname() {
		String path = parent.getPathname();
		if (path.length() != FileSystem.SEPARATOR.length()) {
			path += FileSystem.SEPARATOR;
		}
		path += name;
		return path;
	}

	/**
	 * Get the name of this project file
	 * @return the name
	 */
	String getName() {
		return name;
	}

	/**
	 * Get the parent folder for this file.
	 * @return the parent
	 */
	GhidraFolderData getParent() {
		return parent;
	}

	/**
	 * @return {@link DomainFile} instance which corresponds to this file.
	 */
	GhidraFile getDomainFile() {
		return new GhidraFile(parent.getDomainFolder(), name);
	}

	/**
	 * Get a remote Ghidra URL for this domain file if available within a remote repository.
	 * @param ref reference within a file, may be null.  NOTE: such reference interpretation
	 * is specific to a domain object and tooling with limited support.
	 * @return remote Ghidra URL for this file or null
	 */
	URL getSharedProjectURL(String ref) {
		synchronized (fileSystem) {
			RepositoryAdapter repository = projectData.getRepository();
			if (versionedFolderItem != null && repository != null) {
				URL folderURL = parent.getDomainFolder().getSharedProjectURL();
				try {
					String spec = name;
					if (!StringUtils.isEmpty(ref)) {
						spec += "#" + ref;
					}
					return new URL(folderURL, spec);
				}
				catch (MalformedURLException e) {
					// ignore
				}
			}
			return null;
		}
	}

	/**
	 * Get a local Ghidra URL for this domain file if available within a non-transient local 
	 * project.  A null value is returned for a transient project.
	 * @param ref reference within a file, may be null.  NOTE: such reference interpretation
	 * is specific to a domain object and tooling with limited support.
	 * @return local Ghidra URL for this file or null if transient or not applicable
	 */
	URL getLocalProjectURL(String ref) {
		synchronized (fileSystem) {
			ProjectLocator projectLocator = parent.getProjectLocator();
			if (!projectLocator.isTransient()) {
				return GhidraURL.makeURL(projectLocator, getPathname(), ref);
			}
			return null;
		}
	}

	/**
	 * Reassign a new file-ID to resolve file-ID conflict.
	 * Conflicts can occur as a result of a cancelled check-out.
	 * @throws IOException if an IO error occurs
	 */
	void resetFileID() throws IOException {
		synchronized (fileSystem) {
			if (versionedFolderItem != null || isCheckedOut()) {
				throw new IOException("File ID reset not permitted on versioned file");
			}
			if (folderItem != null) {
				fileID = folderItem.resetFileID();
			}
		}
	}

	/**
	 * Set the name on this file.
	 * @param newName domain file name
	 * @return renamed domain file (older DomainFile instances becomes invalid since they are immutable) 
	 * @throws InvalidNameException if newName contains illegal characters
	 * @throws DuplicateFileException if a file named newName 
	 * already exists in this files domain folder.
	 * @throws FileInUseException if this file is in-use / checked-out.
	 * @throws IOException if an IO or access error occurs.
	 */
	GhidraFile setName(String newName) throws InvalidNameException, IOException {
		synchronized (fileSystem) {
			if (fileSystem.isReadOnly()) {
				throw new ReadOnlyException("setName permitted within writeable project only");
			}
			checkInUse();
			if (parent.containsFile(newName)) {
				throw new DuplicateFileException("File named " + newName + " already exists.");
			}

			String oldName = name;
			String folderPath = parent.getPathname();

			if (isHijacked()) {
				fileSystem.moveItem(folderPath, name, folderPath, newName);
				folderItem = null;
				parent.fileChanged(name);
				parent.fileChanged(newName);
				return parent.getDomainFile(newName);
			}

			if (versionedFolderItem == null) {
				if (!isCheckedOut()) {
					fileSystem.moveItem(folderPath, name, folderPath, newName);
					folderItem = fileSystem.getItem(folderPath, newName);
				}
				else {
					throw new FileInUseException(name + " is checked-out");
				}
			}
			else {
				versionedFileSystem.moveItem(folderPath, name, folderPath, newName);
				versionedFolderItem = versionedFileSystem.getItem(folderPath, newName);
			}

			name = newName;
			parent.fileRenamed(oldName, newName);

			return parent.getDomainFile(newName);
		}
	}

	/**
	 * Returns content-type string for this file
	 * @return the file content type or a reserved content type {@link ContentHandler#MISSING_CONTENT}
	 * or {@link ContentHandler#UNKNOWN_CONTENT}.
	 */
	String getContentType() {
		synchronized (fileSystem) {
			FolderItem item = folderItem != null ? folderItem : versionedFolderItem;
			// this can happen when we are trying to load a version file from
			// a server to which we are not connected
			if (item == null) {
				return ContentHandler.MISSING_CONTENT;
			}
			String contentType = item.getContentType();
			return contentType != null ? contentType : ContentHandler.UNKNOWN_CONTENT;
		}
	}

	/**
	 * Get content handler for this file
	 * @return content handler
	 * @throws IOException if an IO error occurs, file not found, or unsupported content
	 */
	ContentHandler<?> getContentHandler() throws IOException {
		synchronized (fileSystem) {
			FolderItem item = folderItem != null ? folderItem : versionedFolderItem;
			// this can happen when we are trying to load a version file from
			// a server to which we are not connected
			if (item == null) {
				throw new FileNotFoundException(name + " not found");
			}
			return DomainObjectAdapter.getContentHandler(item.getContentType());
		}
	}

	/**
	 * Returns the underlying Class for the domain object in this domain file.
	 * @return the class or null if does not correspond to a domain object.
	 */
	Class<? extends DomainObject> getDomainObjectClass() {
		synchronized (fileSystem) {
			try {
				return getContentHandler().getDomainObjectClass();
			}
			catch (IOException e) {
				// ignore missing content handler
			}
			return DomainObject.class;
		}
	}

	/**
	 * Returns changes made to versioned file by others since checkout was performed.
	 * NOTE: This method is unable to cope with version issues which may require an
	 * upgrade.
	 * @return change set or null
	 * @throws VersionException latest version was created with a different version of software
	 * which prevents rapid determination of change set.
	 * @throws IOException if a folder item access error occurs or change set was 
	 * produced by newer version of software and can not be read
	 */
	ChangeSet getChangesByOthersSinceCheckout() throws VersionException, IOException {
		synchronized (fileSystem) {
			if (versionedFolderItem != null && folderItem != null && folderItem.isCheckedOut()) {
				return getContentHandler().getChangeSet(versionedFolderItem,
					folderItem.getCheckoutVersion(), versionedFolderItem.getCurrentVersion());
			}
			return null;
		}
	}

	/**
	 * Returns the domainObject for this DomainFile only if it is already open.
	 * @return the already opened domainObject or null if it is not currently open.
	 */
	private DomainObjectAdapter getOpenedDomainObject() {
		return projectData.getOpenedDomainObject(getPathname());
	}

	/**
	 * Opens and returns the current domain object.  If the domain object is already opened,
	 * then the existing open domain object is returned.
	 * @param consumer consumer of the domain object which is responsible for
	 * releasing it after use. When all the consumers using the domain object release it, then
	 * the object is closed and its resources released.
	 * @param okToUpgrade if true, allows the system to upgrade out of data domain objects to
	 * be in compliance with the current version of Ghidra. A Version exception will be thrown
	 * if the domain object cannot be upgraded OR okToUpgrade is false and the domain object is
	 * out of date.
	 * @param okToRecover if true, allows the system to recover unsaved file changes which 
	 * resulted from a crash.  If false, any existing recovery data will be deleted.
	 * This flag is only relevant if project is open for update (isInProject) and the file can be
	 * opened for update.
	 * @param monitor permits monitoring of open progress.
	 * @return an open domain object can be modified and saved. (Not read-only)
	 * @throws VersionException if the domain object could not be read due
	 * to a version format change.  If okToUpgrade is true, then a VersionException indicates
	 * that the domain object cannot be upgraded to the current format.  If okToUpgrade is false,
	 * then the VersionException only means the object is not in the current format - it 
	 * may or may not be possible to upgrade. 
	 * @throws IOException if an IO or access error occurs.
	 * @throws CancelledException if monitor cancelled operation
	 */
	DomainObject getDomainObject(Object consumer, boolean okToUpgrade, boolean okToRecover,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {

		// Don't allow this call while versioning operation is on-going
		if (busy.get()) {
			throw new FileInUseException("Cannot open during versioning operation");
		}

		FolderItem myFolderItem;
		DomainObjectAdapter domainObj = null;
		synchronized (fileSystem) {
			if (fileSystem.isReadOnly() || isLinkFile()) {
				return getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);
			}
			domainObj = getOpenedDomainObject();
			if (domainObj != null) {
				if (!domainObj.addConsumer(consumer)) {
					domainObj = null;
					projectData.clearDomainObject(getPathname());
				}
				else {
					return domainObj;
				}
			}
			ContentHandler<?> contentHandler = getContentHandler();
			if (folderItem == null) {
				DomainObjectAdapter doa = contentHandler.getReadOnlyObject(versionedFolderItem,
					DomainFile.DEFAULT_VERSION, true, consumer, monitor);
				doa.setChanged(false);
				DomainFileProxy proxy = new DomainFileProxy(name, parent.getPathname(), doa,
					DomainFile.DEFAULT_VERSION, fileID, parent.getProjectLocator());
				proxy.setLastModified(getLastModifiedTime());
				return doa;
			}
			myFolderItem = folderItem;

			domainObj = contentHandler.getDomainObject(myFolderItem, parent.getUserFileSystem(),
				FolderItem.DEFAULT_CHECKOUT_ID, okToUpgrade, okToRecover, consumer, monitor);
			projectData.setDomainObject(getPathname(), domainObj);

			// Notify file manager of in-use domain object.
			// A link-file object is indirect with tracking intiated by the URL-referenced file.
			if (!isLinkFile()) {
				projectData.trackDomainFileInUse(domainObj);
			}
		}

		// Set domain file for newly opened domain object
		// NOTE: Some domain object implementations may throw RuntimeExceptions
		// so cleanup is required in those cases
		try {
			domainObj.setDomainFile(getDomainFile());
		}
		catch (Exception e) {
			domainObj.release(consumer);
			projectData.clearDomainObject(getPathname());
			// generate IOException
			Throwable cause = e.getCause();
			if (cause == null) {
				cause = e;
			}
			if (cause instanceof IOException) {
				throw (IOException) cause;
			}
			else if (cause instanceof VersionException) {
				throw (VersionException) cause;
			}
			throw new IOException(e.getMessage(), e);
		}
		listener.domainFileObjectOpenedForUpdate(domainObj.getDomainFile(), domainObj);
		return domainObj;
	}

	/**
	 * Returns a "read-only" version of the domain object.  "Read-only" means that the domain
	 * object cannot be saved back into its original domain object. It can still be modified
	 * and saved to a new domain file.  The domain object will be assigned a temporary domain
	 * file that will not allow a "save" operation. The user must do a "save as"
	 * to a new filename.
	 * @param consumer consumer of the domain object which is responsible for
	 * releasing it after use.
	 * @param version the domain object version requested.  DEFAULT_VERSION should be 
	 * specified to open the current version.  
	 * @param monitor permits monitoring of open progress.
	 * @return a new domain object that is disassociated from its original domain file.
	 * @throws VersionException if the domain object could not be read due
	 * to a version format change.
	 * @throws FileNotFoundException if the stored file/version was not found.
	 * @throws IOException if an IO or access error occurs.
	 * @throws CancelledException if monitor cancelled operation
	 */
	DomainObject getReadOnlyDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		synchronized (fileSystem) {
			FolderItem item =
				(folderItem != null && version == DomainFile.DEFAULT_VERSION) ? folderItem
						: versionedFolderItem;
			DomainObjectAdapter doa =
				getContentHandler().getReadOnlyObject(item, version, true, consumer, monitor);
			doa.setChanged(false);

			// Notify file manager of in-use domain object.
			// A link-file object is indirect with tracking intiated by the URL-referenced file.
			if (!isLinkFile()) {
				projectData.trackDomainFileInUse(doa);
			}

			DomainFileProxy proxy = new DomainFileProxy(name, getParent().getPathname(), doa,
				version, fileID, parent.getProjectLocator());
			proxy.setLastModified(getLastModifiedTime());
			return doa;
		}
	}

	/**
	 * Returns a new DomainObject that cannot be changed or saved to its original file.
	 * NOTE: The use of this method should generally be avoided since it can't
	 * handle version changes that may have occured and require a data upgrade
	 * (e.g., DB schema change).
	 * @param consumer consumer of the domain object which is responsible for
	 * releasing it after use.
	 * @param version the domain object version requested.  DEFAULT_VERSION should be 
	 * specified to open the current version.  
	 * @param monitor permits monitoring of open progress.
	 * @return a new domain object that is disassociated from its original domain file
	 * and cannot be modified
	 * @throws VersionException if the domain object could not be read due
	 * to a version format change.
	 * @throws FileNotFoundException if the stored file/version was not found.
	 * @throws IOException if an IO or access error occurs.
	 * @throws CancelledException if monitor cancelled operation
	 */
	DomainObject getImmutableDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		synchronized (fileSystem) {
			DomainObjectAdapter obj = null;
			ContentHandler<?> contentHandler = getContentHandler();
			if (versionedFolderItem == null ||
				(version == DomainFile.DEFAULT_VERSION && folderItem != null) || isHijacked()) {
				obj = contentHandler.getImmutableObject(folderItem, consumer, version, -1, monitor);
			}
			else {
				obj = contentHandler.getImmutableObject(versionedFolderItem, consumer, version, -1,
					monitor);
			}

			// Notify file manager of in-use domain object.
			// A link-file object is indirect with tracking intiated by the URL-referenced file.
			if (!isLinkFile()) {
				projectData.trackDomainFileInUse(obj);
			}

			DomainFileProxy proxy = new DomainFileProxy(name, getParent().getPathname(), obj,
				version, fileID, parent.getProjectLocator());
			proxy.setLastModified(getLastModifiedTime());
			return obj;
		}
	}

	/**
	 * Prior to invoking getDomainObject, this method can be used to determine if
	 * unsaved changes can be recovered on the next open.
	 * @return true if recovery data exists.
	 */
	boolean canRecover() {
		synchronized (fileSystem) {
			DomainObjectAdapter dobj = getOpenedDomainObject();
			if (!fileSystem.isReadOnly() && folderItem != null && dobj == null) {
				return folderItem.canRecover();
			}
			return false;
		}
	}

	/**
	 * If the file has an updatable domain object with unsaved changes, generate a recovery 
	 * snapshot.
	 * @return true if snapshot successful or not needed, false if file is busy which prevents 
	 * snapshot, or snapshot was cancelled.
	 * @throws IOException if there is an exception saving the snapshot
	 */
	boolean takeRecoverySnapshot() throws IOException {
		if (fileSystem.isReadOnly()) {
			return true;
		}
		DomainObjectAdapter dobj = projectData.getOpenedDomainObject(getPathname());
		if (!(dobj instanceof DomainObjectAdapterDB) || !dobj.isChanged()) {
			return true;
		}
		LockingTaskMonitor monitor = null;
		DomainObjectAdapterDB dbObjDB = (DomainObjectAdapterDB) dobj;
		if (busy.getAndSet(true)) {
			return false; // snapshot must be postponed
		}
		try {
			monitor = dbObjDB.lockForSnapshot(true, "Recovery Snapshot Task");
			if (monitor == null) {
				return true;
			}
			monitor.setMessage(getName());
			return dbObjDB.getDBHandle().takeRecoverySnapshot(dbObjDB.getChangeSet(), monitor);
		}
		catch (CancelledException e) {
			return false;
		}
		finally {
			busy.set(false);
			if (monitor != null) {
				monitor.releaseLock(); // releases lock
			}
		}
	}

	/**
	 * Get a long value representing the time when the data was last modified.
	 * @return the time
	 */
	long getLastModifiedTime() {
		synchronized (fileSystem) {
			if (folderItem != null) {
				return folderItem.lastModified();
			}
			if (versionedFolderItem != null) {
				return versionedFolderItem.lastModified();
			}
			return 0;
		}
	}

	/**
	 * Get the state based Icon image for the domain file based upon its content class.
	 * @param disabled true if the icon return should be rendered as 
	 * not enabled
	 * @return image icon
	 */
	Icon getIcon(boolean disabled) {
		if (disabled) {
			if (disabledIcon == null) {
				disabledIcon = generateIcon(true);
			}
			return disabledIcon;
		}
		if (icon == null) {
			icon = generateIcon(false);
		}
		return icon;
	}

	private Icon generateIcon(boolean disabled) {
		if (parent == null) {
			// instance has been disposed
			return DomainFile.UNSUPPORTED_FILE_ICON;
		}
		synchronized (fileSystem) {

			boolean isLink = isLinkFile();

			FolderItem item = folderItem != null ? folderItem : versionedFolderItem;

			Icon baseIcon = new TranslateIcon(getBaseIcon(item), 1, 1);

			if (versionedFolderItem != null) {
				MultiIcon multiIcon = new MultiIcon(VERSION_ICON, disabled);
				multiIcon.addIcon(baseIcon);
				if (isHijacked()) {
					multiIcon.addIcon(HIJACKED_ICON);
				}
				else if (isCheckedOut()) {
					if (isCheckedOutExclusive()) {
						multiIcon.addIcon(CHECKED_OUT_EXCLUSIVE_ICON);
					}
					else {
						if (getVersion() == getLatestVersion()) {
							multiIcon.addIcon(CHECKED_OUT_ICON);
						}
						else {
							multiIcon.addIcon(NOT_LATEST_CHECKED_OUT_ICON);
						}
					}
				}
				if (isLink) {
					multiIcon.addIcon(new TranslateIcon(LinkHandler.LINK_ICON, 0, 1));
				}
				return multiIcon;
			}
			else if (folderItem != null) {
				MultiIcon multiIcon = new MultiIcon(baseIcon, disabled, ICON_WIDTH, ICON_HEIGHT);
				if (isReadOnly() && !fileSystem.isReadOnly()) {
					multiIcon.addIcon(new TranslateIcon(READ_ONLY_ICON, 8, 9));
				}
				if (isCheckedOut()) {
					if (isCheckedOutExclusive()) {
						multiIcon.addIcon(CHECKED_OUT_EXCLUSIVE_ICON);
					}
					else {
						multiIcon.addIcon(CHECKED_OUT_ICON);
					}
				}
				if (isLink) {
					multiIcon.addIcon(new TranslateIcon(LinkHandler.LINK_ICON, 0, 1));
				}
				return multiIcon;
			}
		}
		return DomainFile.UNSUPPORTED_FILE_ICON;
	}

	private Icon getBaseIcon(FolderItem item) {
		try {
			return getContentHandler().getIcon();
		}
		catch (IOException e) {
			// ignore missing content handler
		}
		return DomainFile.UNSUPPORTED_FILE_ICON;
	}

	/**
	 * Return whether the domain object in this domain file has changed.
	 * @return true if changed
	 */
	boolean isChanged() {
		DomainObjectAdapter dobj = getOpenedDomainObject();
		return dobj != null && dobj.isChanged();
	}

	/**
	 * Returns true if this is a checked-out file.
	 * @return true if checked-out
	 */
	boolean isCheckedOut() {
		synchronized (fileSystem) {
			return folderItem != null && folderItem.isCheckedOut();
		}
	}

	/**
	 * Returns true if this a checked-out file with exclusive access.
	 * @return true if checked-out exclusively
	 */
	boolean isCheckedOutExclusive() {
		synchronized (fileSystem) {
			if (folderItem == null) {
				return false;
			}
			if (folderItem.isCheckedOutExclusive()) {
				return true;
			}
			// All checkouts for non-shared versioning are treated as exclusive
			return !versionedFileSystem.isShared() && folderItem.isCheckedOut();
		}
	}

	/**
	 * Returns true if this is a checked-out file which has been modified since it was checked-out.
	 * @return true if modified since check-out
	 */
	boolean modifiedSinceCheckout() {
		synchronized (fileSystem) {
			return isCheckedOut() &&
				folderItem.getCurrentVersion() != folderItem.getLocalCheckoutVersion();
		}
	}

	/**
	 * Returns whether this file is explicitly marked as read-only.  This method is only supported
	 * by the local file system and does not apply to a versioned file that is not checked-out.
	 * A versioned file that is not checked-out will always return false, while a 
	 * {@link DomainFileProxy} will always return true.
	 * From a framework point of view a read-only file can never be changed.
	 * @return true if this file is marked read-only
	 */
	boolean isReadOnly() {
		synchronized (fileSystem) {
			return folderItem != null && folderItem.isReadOnly();
		}
	}

	/**
	 * Return true if this is a versioned database, else false
	 * @return true if versioned
	 */
	boolean isVersioned() {
		synchronized (fileSystem) {
			if (versionedFolderItem == null) {
				return isCheckedOut();
			}
			return !isHijacked();
		}
	}

	/**
	 * Returns true if the file is versioned but a private copy also exists.
	 * @return true if hijacked
	 */
	boolean isHijacked() {
		synchronized (fileSystem) {
			return folderItem != null && versionedFolderItem != null && !folderItem.isCheckedOut();
		}
	}

	/**
	 * Returns true if this file may be checked-out from the associated repository.
	 * User's with read-only repository access will not have checkout ability.
	 * @return true if can checkout
	 */
	boolean canCheckout() {
		synchronized (fileSystem) {
			try {
				if (folderItem != null || fileSystem.isReadOnly() ||
					versionedFileSystem.isReadOnly()) {
					return false;
				}
				return !isLinkFile();
			}
			catch (IOException e) {
				return false;
			}
		}
	}

	/**
	 * Returns true if this file may be checked-in to the associated repository.
	 * @return true if can check-in
	 */
	boolean canCheckin() {
		synchronized (fileSystem) {
			try {
				return (!fileSystem.isReadOnly() && !versionedFileSystem.isReadOnly() &&
					modifiedSinceCheckout());
			}
			catch (IOException e) {
				return false;
			}
		}
	}

	/**
	 * Return either the latest version if the file is not checked-out or the version that
	 * was checked-out or a specific version that was requested.
	 * @return the version
	 */
	int getVersion() {
		synchronized (fileSystem) {
			try {
				if (folderItem != null) {
					if (folderItem.isCheckedOut()) {
						return folderItem.getCheckoutVersion();
					}
					return folderItem.getCurrentVersion();
				}
				return versionedFolderItem.getCurrentVersion();
			}
			catch (IOException e) {
				Msg.error(this, "IO error", e);
				return -1;
			}
		}
	}

	/**
	 * Returns true if this file represents the latest version of the associated domain object.
	 * @return true if the latest version
	 */
	int getLatestVersion() {
		synchronized (fileSystem) {
			if (!isHijacked() && versionedFolderItem != null) {
				return versionedFolderItem.getCurrentVersion();
			}
			return 0;
		}
	}

	/**
	 * Returns true if this file can be merged with the current versioned file.
	 * @return true if can merge
	 */
	boolean canMerge() {
		synchronized (fileSystem) {
			try {
				return (!fileSystem.isReadOnly() && versionedFolderItem != null &&
					folderItem != null && folderItem.isCheckedOut() &&
					(versionedFolderItem.getCurrentVersion() > folderItem.getCheckoutVersion()));
			}
			catch (IOException e) {
				Msg.error(this, "IO Error", e);
			}
			return false;
		}
	}

	/**
	 * Sets the object to read-only.  This method may only be invoked
	 * for private files (i.e., not versioned).
	 * @param state if true file will be read-only and may not be updated, if false the 
	 * file may be updated.
	 * @throws IOException if an IO error occurs.
	 */
	void setReadOnly(boolean state) throws IOException {
		synchronized (fileSystem) {
			if (fileSystem.isReadOnly()) {
				throw new ReadOnlyException("setReadOnly permitted in writeable project only");
			}
			if (isVersioned()) {
				throw new AssertException("Versioned files do not support read-only setting");
			}
			folderItem.setReadOnly(state);
			statusChanged();
		}
	}

	/**
	 * Returns list of all available versions.
	 * @return the versions
	 * @throws IOException if there is an exception getting the history
	 */
	Version[] getVersionHistory() throws IOException {
		synchronized (fileSystem) {
			if (versionedFolderItem != null) {
				return versionedFolderItem.getVersions();
			}
			return null;
		}
	}

	/**
	 * Perform neccessary check to ensure this file may be added to version control.
	 * @throws IOException if any checks fail or other IO error occurs
	 */
	void checkCanAddToRepository() throws IOException {
		if (!versionedFileSystem.isOnline()) {
			throw new NotConnectedException("Not connected to repository server");
		}
		if (fileSystem.isReadOnly() || versionedFileSystem.isReadOnly()) {
			throw new ReadOnlyException(
				"versioning permitted within writeable project and repository only");
		}
		if (folderItem == null) {
			throw new FileNotFoundException("File not found");
		}
		if (folderItem.isCheckedOut() || versionedFolderItem != null) {
			throw new IOException("File already versioned");
		}
		ContentHandler<?> contentHandler = getContentHandler();
		if (contentHandler instanceof LinkHandler linkHandler) {
			// must check local vs remote URL
			if (!GhidraURL.isServerRepositoryURL(LinkHandler.getURL(folderItem))) {
				throw new IOException("Local project link-file may not be versioned");
			}
		}
		else if (contentHandler.isPrivateContentType()) {
			throw new IOException("Content may not be versioned: " + getContentType());
		}
	}

	/** 
	 * Adds this private file to version control.
	 * @param comment new version comment
	 * @param keepCheckedOut if true, the file will be initially checked-out
	 * @param monitor progress monitor
	 * @throws FileInUseException if this file is in-use.
	 * @throws IOException if an IO or access error occurs.  Also if file is not 
	 * private.
	 * @throws CancelledException if the monitor cancelled the operation
	 */
	void addToVersionControl(String comment, boolean keepCheckedOut, TaskMonitor monitor)
			throws IOException, CancelledException {

		checkCanAddToRepository();

		if (busy.getAndSet(true)) {
			throw new FileInUseException(name + " is busy");
		}

		DomainObjectAdapterDB inUseDomainObj = null;
		projectData.mergeStarted();
		try {
			inUseDomainObj = getAndLockInUseDomainObjectForMergeUpdate("checkin");

			if (isLinkFile()) {
				keepCheckedOut = false;
			}
			else if (inUseDomainObj != null && !keepCheckedOut) {
				keepCheckedOut = true;
				Msg.warn(this, "File currently open - must keep checked-out: " + name);
			}

			synchronized (fileSystem) {

				String parentPath = parent.getPathname();
				String user = ClientUtil.getUserName();
				try {
					if (folderItem instanceof DatabaseItem) {
						DatabaseItem databaseItem = (DatabaseItem) folderItem;
						BufferFile bufferFile = databaseItem.open();
						try {
							versionedFolderItem = versionedFileSystem.createDatabase(parentPath,
								name, folderItem.getFileID(), bufferFile, comment,
								folderItem.getContentType(), false, monitor, user);
						}
						finally {
							bufferFile.dispose();
						}
					}
					else if (folderItem instanceof DataFileItem) {
						DataFileItem dataFileItem = (DataFileItem) folderItem;
						InputStream istream = dataFileItem.getInputStream();
						try {
							versionedFolderItem = versionedFileSystem.createDataFile(parentPath,
								name, istream, comment, folderItem.getContentType(), monitor);
						}
						finally {
							istream.close();
						}
					}
					else {
						throw new AssertException("Unknown folder item type");
					}
				}
				catch (InvalidNameException e) {
					throw new AssertException("Unexpected error", e);
				}

				if (keepCheckedOut) {

					// Maintain exclusive chekout if private repository or file is open for update
					boolean exclusive = !versionedFileSystem.isShared() || (inUseDomainObj != null);

					ProjectLocator projectLocator = parent.getProjectLocator();
					CheckoutType checkoutType;
					if (projectLocator.isTransient()) {
						checkoutType = CheckoutType.TRANSIENT;
						exclusive = true;
					}
					else {
						// All checkouts for non-shared versioning are treated as exclusive
						checkoutType =
							(exclusive || !versionedFileSystem.isShared()) ? CheckoutType.EXCLUSIVE
									: CheckoutType.NORMAL;
					}
					ItemCheckoutStatus checkout = versionedFolderItem.checkout(checkoutType, user,
						ItemCheckoutStatus.getProjectPath(projectLocator.toString(),
							projectLocator.isTransient()));
					folderItem.setCheckout(checkout.getCheckoutId(), exclusive,
						checkout.getCheckoutVersion(), folderItem.getCurrentVersion());
				}
				else {
					// NOTE: file open read-only may prevent removal and result in hijack
					try {
						folderItem.delete(-1, ClientUtil.getUserName());
						folderItem = null;
					}
					catch (FileInUseException e1) {
						// Ignore - should result in Hijacked file
					}
				}

				if (inUseDomainObj != null) {
					getContentHandler().resetDBSourceFile(folderItem, inUseDomainObj);
				}
			} // end of synchronized block

			if (inUseDomainObj != null) {
				inUseDomainObj.invalidate();
			}
		}
		finally {
			unlockDomainObject(inUseDomainObj);
			busy.set(false);
			projectData.mergeEnded();
			parent.deleteLocalFolderIfEmpty();
			parent.fileChanged(name);
		}
	}

	/**
	 * Checkout this file for update.  If this file is already 
	 * private, this method does nothing.
	 * @param exclusive if true an exclusive checkout will be requested 
	 * @param monitor progress monitor
	 * @return true if checkout successful, false if an exclusive checkout was not possible
	 * due to other users having checkouts of this file.  A request for a non-exclusive checkout 
	 * will never return false.
	 * @throws IOException if an IO or access error occurs.
	 * @throws CancelledException if task monitor cancelled operation.
	 */
	boolean checkout(boolean exclusive, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException("checkout permitted in writeable project only");
		}
		if (versionedFileSystem.isReadOnly()) {
			throw new ReadOnlyException(
				"Versioned repository is read-only and does not permit checkout");
		}
		synchronized (fileSystem) {
			if (folderItem != null) {
				throw new AssertException("Cannot checkout, private file exists");
			}
			if (!versionedFileSystem.isOnline()) {
				throw new NotConnectedException("Not connected to repository server");
			}
			if (isLinkFile()) {
				return false;
			}
			String user = ClientUtil.getUserName();
			ProjectLocator projectLocator = parent.getProjectLocator();
			CheckoutType checkoutType;
			if (projectLocator.isTransient()) {
				checkoutType = CheckoutType.TRANSIENT;
				exclusive = true;
			}
			else {
				// All checkouts for non-shared versioning are treated as exclusive
				checkoutType =
					(exclusive || !versionedFileSystem.isShared()) ? CheckoutType.EXCLUSIVE
							: CheckoutType.NORMAL;
			}
			ItemCheckoutStatus checkout =
				versionedFolderItem.checkout(checkoutType, user, ItemCheckoutStatus
						.getProjectPath(projectLocator.toString(), projectLocator.isTransient()));
			if (checkout == null) {
				return false;
			}

			// FileID may be established during an exclusive checkout
			boolean fileIDset = false;
			if (fileID == null) {
				fileID = versionedFolderItem.getFileID();
				fileIDset = (fileID != null);
			}

			int checkoutVersion = checkout.getCheckoutVersion();
			String parentPath = parent.getPathname();

			try {
				if (versionedFolderItem instanceof DatabaseItem) {
					DatabaseItem databaseItem = (DatabaseItem) versionedFolderItem;
					BufferFile bufferFile = databaseItem.open(checkoutVersion);
					try {
						folderItem = fileSystem.createDatabase(parentPath, name, fileID, bufferFile,
							null, databaseItem.getContentType(), false, monitor, user);
					}
					finally {
						bufferFile.dispose();
					}
				}
				else if (versionedFolderItem instanceof DataFileItem) {
					DataFileItem dataFileItem = (DataFileItem) versionedFolderItem;
					InputStream istream = dataFileItem.getInputStream(checkoutVersion);
					try {
						folderItem = fileSystem.createDataFile(parentPath, name, istream, null,
							dataFileItem.getContentType(), monitor);
					}
					finally {
						istream.close();
					}
				}
				else {
					throw new AssertException("Can't checkout - unknown file type");
				}
			}
			catch (InvalidNameException e) {
				throw new AssertException("Unexpected error", e);
			}
			finally {
				if (folderItem == null) {
					versionedFolderItem.terminateCheckout(checkout.getCheckoutId(), false);
				}
			}
			folderItem.setCheckout(checkout.getCheckoutId(), exclusive, checkoutVersion,
				folderItem.getCurrentVersion());

			statusChanged(fileIDset);
		}
		return true;
	}

	private boolean quickCheckin(CheckinHandler checkinHandler, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (!(versionedFolderItem instanceof DatabaseItem)) {
			return false;
		}

		monitor.checkCancelled();
		monitor.setMessage("Initiating Check In for " + name);
		boolean success = false;
		LocalManagedBufferFile srcFile = null;
		ManagedBufferFile checkinFile = null;

		try {
			synchronized (fileSystem) {
				// Make sure version does not change by opening for update before checking versions
				checkinFile =
					((DatabaseItem) versionedFolderItem).openForUpdate(folderItem.getCheckoutId());
				if (versionedFolderItem.getCurrentVersion() != folderItem.getCheckoutVersion()) {
					return false;
				}
				// TODO: assumes folderItem is local - should probably defer createNewVersion 
				// to folderItem if possible (requires refactor)
				srcFile = (LocalManagedBufferFile) ((DatabaseItem) folderItem).open();
			}

			String comment = checkinHandler.getComment();
			if (checkinHandler.createKeepFile()) {
				DomainObject sourceObj = null;
				try {
					sourceObj = getContentHandler().getImmutableObject(folderItem, this,
						DomainFile.DEFAULT_VERSION, -1, monitor);
					createKeepFile(sourceObj, monitor);
				}
				catch (VersionException e) {
					// ignore - unable to create keep file
				}
				finally {
					release(sourceObj);
				}
			}
			monitor.checkCancelled();
			synchronized (fileSystem) {
				srcFile.createNewVersion(checkinFile, comment, monitor);
				success = true;
			}
		}
		finally {
			if (checkinFile != null) {
				checkinFile.close();
			}
			if (srcFile != null) {
				srcFile.close();
			}
		}
		return success;
	}

	/**
	 * Verify checkout status and that current user is the checkout user for this file
	 * @param operationName name of user case (e.g., checkin)
	 * @throws IOException if server/repository will not permit current user to checkin,
	 * or update checkout version of current file.  (i.e., server login does not match
	 * user name used at time of initial checkout)
	 */
	private void verifyCheckout(String operationName) throws IOException {
		if (versionedFileSystem instanceof LocalFileSystem) {
			return; // rely on local project ownership
		}
		String repoUserName = versionedFileSystem.getUserName();
		if (repoUserName == null) {
			throw new IOException("File " + operationName + " not permitted (not connected)");
		}
		ItemCheckoutStatus checkoutStatus = getCheckoutStatus();
		if (checkoutStatus == null) {
			throw new IOException("File not checked out");
		}
		String checkoutUserName = checkoutStatus.getUser();
		if (!repoUserName.equals(checkoutUserName)) {
			throw new IOException("File " + operationName + " not permitted - checkout user '" +
				checkoutUserName + "' differs from repository user '" + repoUserName + "'");
		}
	}

	/**
	 * Performs check in to associated repository.  File must be checked-out 
	 * and modified since checkout.
	 * @param checkinHandler provides user input data to complete checkin process.
	 * @param monitor the TaskMonitor.
	 * @throws IOException if an IO or access error occurs
	 * @throws VersionException if unable to handle domain object version in versioned filesystem.
	 * We are unable to upgrade since this would only occur if checkout is not exclusive.
	 * @throws CancelledException if task monitor cancelled operation
	 */
	void checkin(CheckinHandler checkinHandler, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {

		if (!versionedFileSystem.isOnline()) {
			throw new NotConnectedException("Not connected to repository server");
		}
		if (fileSystem.isReadOnly() || versionedFileSystem.isReadOnly()) {
			throw new ReadOnlyException(
				"checkin permitted within writeable project and repository only");
		}
		if (!isCheckedOut()) {
			throw new IOException("File not checked out");
		}
		if (isChanged()) {
			throw new IOException("File has unsaved changes");
		}
		if (canRecover()) {
			throw new IOException("File recovery data exists");
		}
		if (!modifiedSinceCheckout()) {
			throw new IOException("File has not been modified since checkout");
		}
		verifyCheckout("checkin");
		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}

		if (busy.getAndSet(true)) {
			throw new FileInUseException(name + " is busy");
		}

		DomainObjectAdapterDB inUseDomainObj = null;
		projectData.mergeStarted();
		try {
			ContentHandler<?> contentHandler = getContentHandler();

			inUseDomainObj = getAndLockInUseDomainObjectForMergeUpdate("checkin");

			boolean keepCheckedOut = checkinHandler.keepCheckedOut();

			if (inUseDomainObj != null && !keepCheckedOut) {
				keepCheckedOut = true;
				Msg.warn(this, "File currently open - must keep checked-out: " + name);
			}

			boolean quickCheckin = ALWAYS_MERGE ? false : quickCheckin(checkinHandler, monitor);

			if (!quickCheckin) {

				if (SystemUtilities.isInHeadlessMode()) {
					throw new IOException(
						"Checkin failed, file requires merge which is not supported in headless mode");
				}

				Msg.info(this, "Checkin with merge for " + name);

				DomainObjectAdapter checkinObj = contentHandler.getDomainObject(versionedFolderItem,
					null, folderItem.getCheckoutId(), false, false, this, monitor);
				checkinObj.setDomainFile(new DomainFileProxy(name, getParent().getPathname(),
					checkinObj, versionedFolderItem.getCurrentVersion() + 1, fileID,
					parent.getProjectLocator()));

				DomainObject sourceObj = null;
				DomainObject originalObj = null;
				DomainObject latestObj = null;
				try {
					synchronized (fileSystem) {
						int coVer = folderItem.getCheckoutVersion();
						sourceObj = contentHandler.getImmutableObject(folderItem, this,
							DomainFile.DEFAULT_VERSION, -1, monitor);
						originalObj = contentHandler.getImmutableObject(versionedFolderItem, this,
							coVer, -1, monitor);
						latestObj = contentHandler.getImmutableObject(versionedFolderItem, this,
							DomainFile.DEFAULT_VERSION, coVer, monitor);
					}
					DomainObjectMergeManager mergeMgr = contentHandler.getMergeManager(checkinObj,
						sourceObj, originalObj, latestObj);

					if (!mergeMgr.merge(monitor)) {
						Msg.info(this, "Checkin with merge terminated for " + name);
						return; // error displayed by merge manager
					}

					checkinObj.save(checkinHandler.getComment(), monitor);

					if (checkinHandler.createKeepFile()) {
						if (monitor != null) {
							monitor.setMessage("Generating local keep file...");
						}
						createKeepFile(sourceObj, monitor);
					}

				}
				finally {
					checkinObj.release(this);
					release(sourceObj);
					release(originalObj);
					release(latestObj);
				}
			}

			synchronized (fileSystem) {

				versionedFolderItem = versionedFileSystem.getItem(parent.getPathname(), name);
				if (versionedFolderItem == null) {
					throw new IOException("Checkin failed, versioned item not found");
				}

				Msg.info(this, "Checkin completed for " + name);

				if (keepCheckedOut) {
					boolean success = false;
					try {
						if (monitor != null) {
							monitor.setMessage("Updating local checkout file...");
						}
						folderItem.updateCheckout(versionedFolderItem, !quickCheckin, monitor);
						success = true;
					}
					finally {
						if (!success) {
							// Failed to update checkout for unknown reason
							try {
								if (inUseDomainObj != null) {
									// On error disassociate open domain object from this file
									projectData.clearDomainObject(getPathname());
									// An invalid version (-2) is specified to avoid file match
									inUseDomainObj.setDomainFile(new DomainFileProxy(name,
										parent.getPathname(), inUseDomainObj, -2, fileID,
										parent.getProjectLocator()));
									inUseDomainObj.setTemporary(true);
								}
								undoCheckout(false, true);
							}
							catch (IOException e) {
								Msg.error(this, "Undo checkout error", e);
							}
						}
					}
				}
				else {
					undoCheckout(false, true);
				}

				if (inUseDomainObj != null) {
					contentHandler.resetDBSourceFile(folderItem, inUseDomainObj);
				}

			} // end of synchronized block

			if (inUseDomainObj != null) {
				inUseDomainObj.invalidate();
			}
		}
		finally {
			unlockDomainObject(inUseDomainObj);
			busy.set(false);
			projectData.mergeEnded();
			parent.deleteLocalFolderIfEmpty();
			parent.fileChanged(name);
		}
	}

	private void release(DomainObject domainObj) {
		if (domainObj != null) {
			domainObj.release(this);
		}
	}

	private void unlockDomainObject(DomainObjectAdapterDB lockedDomainObject) {
		try {
			if (lockedDomainObject != null) {
				lockedDomainObject.unlock();
			}
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected " + getContentType() + " lock error: " + getName());
		}
	}

	private DomainObjectAdapterDB getAndLockInUseDomainObjectForMergeUpdate(String operation)
			throws IOException {
		DomainObjectAdapterDB inUseDomainObj;
		synchronized (fileSystem) {
			DomainObjectAdapter domainObj = getOpenedDomainObject();
			if (domainObj == null) {
				return null;
			}
			// If we proceed with file in-use it must be instance of DomainObjectAdapterDB
			if (!(domainObj instanceof DomainObjectAdapterDB)) {
				throw new FileInUseException(name + " is in use");
			}
			inUseDomainObj = (DomainObjectAdapterDB) domainObj;
			if (inUseDomainObj.isChanged()) {
				throw new FileInUseException(name + " is in use w/ unsaved changes");
			}
		}

		// Ensure that existing domain object will support DB merge update and is can be locked
		ContentHandler<?> contentHandler = getContentHandler();
		if (!contentHandler.canResetDBSourceFile() || !inUseDomainObj.lock(operation) ||
			inUseDomainObj.getDBHandle().hasUncommittedChanges()) {
			throw new FileInUseException(name + " is in use");
		}

		return inUseDomainObj;
	}

	/**
	 * Get checkout status associated with a versioned file.
	 * @return checkout status or null if not checked-out to current associated project.
	 * @throws IOException if an IO or access error occurs
	 */
	ItemCheckoutStatus getCheckoutStatus() throws IOException {
		synchronized (fileSystem) {
			if (!versionedFileSystem.isOnline()) {
				throw new NotConnectedException("Not connected to repository server");
			}
			if (versionedFolderItem == null) {
				throw new IOException("File is not versioned");
			}
			ItemCheckoutStatus status = null;
			if (folderItem != null) {
				long checkoutId = folderItem.getCheckoutId();
				if (checkoutId >= 0) {
					status = versionedFolderItem.getCheckout(checkoutId);
				}
			}
			return status;
		}
	}

	/**
	 * Get a list of checkouts by all users for the associated versioned file.
	 * @return list of checkouts
	 * @throws IOException if an IO or access error occurs
	 */
	ItemCheckoutStatus[] getCheckouts() throws IOException {
		synchronized (fileSystem) {
			if (!versionedFileSystem.isOnline()) {
				throw new NotConnectedException("Not connected to repository server");
			}
			if (versionedFolderItem == null) {
				throw new IOException("File is not versioned");
			}
			return versionedFolderItem.getCheckouts();
		}
	}

	/**
	 * Forcefully terminate a checkout for the associated versioned file.
	 * The user must be the owner of the checkout or have administrator privilege
	 * on the versioned filesystem (i.e., repository).
	 * @param checkoutId checkout ID
	 * @throws IOException if an IO or access error occurs
	 */
	void terminateCheckout(long checkoutId) throws IOException {
		synchronized (fileSystem) {
			if (!versionedFileSystem.isOnline()) {
				throw new NotConnectedException("Not connected to repository server");
			}
			if (versionedFolderItem == null) {
				throw new IOException("File is not versioned");
			}
			versionedFolderItem.terminateCheckout(checkoutId, true);
		}
	}

	/**
	 * Undo "checked-out" file.  The original repository file is restored.
	 * @param keep if true, the private database will be renamed with a .keep
	 * extension.
	 * @param inUseOK true if a busy/in-use file state may be ignored, else false
	 * @throws NotConnectedException if shared project and not connected to repository
	 * @throws FileInUseException if this file is in-use (when {@code inUseOK} == false).
	 * @throws IOException if file is not checked-out or an IO / access error occurs.
	 */
	void undoCheckout(boolean keep, boolean inUseOK) throws IOException {
		undoCheckout(keep, false, inUseOK);
	}

	/**
	 * Undo "checked-out" file.  The original repository file is restored.
	 * @param keep if true, the private database will be renamed with a .keep
	 * extension.
	 * @param force true if operation may be proceed even when not connected to the versioned 
	 * file-system.
	 * @param inUseOK true if a busy/in-use file state may be ignored, else false
	 * @throws NotConnectedException if shared project and not connected to repository
	 * @throws FileInUseException if this file is in-use (when {@code inUseOK} == false).
	 * @throws IOException if file is not checked-out or an IO / access error occurs.
	 */
	void undoCheckout(boolean keep, boolean force, boolean inUseOK) throws IOException {
		synchronized (fileSystem) {
			if (fileSystem.isReadOnly()) {
				throw new ReadOnlyException("undoCheckout permitted within writeable project only");
			}
			if (!inUseOK) {
				checkInUse();
			}
			boolean doForce = false;
			boolean isOnline = versionedFileSystem.isOnline();
			if (!isOnline) {
				if (!force) {
					throw new NotConnectedException("Not connected to repository server");
				}
				doForce = true;
			}
			if (!isCheckedOut()) {
				throw new IOException("File not checked out");
			}
			if (!doForce) {
				verifyCheckout("undo-checkout");
				long checkoutId = folderItem.getCheckoutId();
				versionedFolderItem.terminateCheckout(checkoutId, true);
			}
			String keepName = getKeepName();
			if (keep) {
				folderItem.clearCheckout();
				try {
					// generate new local keep file
					String folderPath = parent.getPathname();
					fileSystem.moveItem(folderPath, name, folderPath, keepName);
					parent.fileChanged(keepName);
				}
				catch (InvalidNameException e) {
					throw new AssertException("Unexpected error", e);
				}
			}
			else {
				folderItem.delete(-1, ClientUtil.getUserName());
				parent.deleteLocalFolderIfEmpty();
			}
			folderItem = null;
			parent.fileChanged(name);
		}
	}

	private String getKeepName() {
		String tempName = name + ".keep";
		String keep = tempName;
		int cnt = 0;
		while (fileSystem.fileExists(parent.getPathname(), keep) || versionedFileExists(keep)) {
			keep = tempName + "." + (++cnt);
		}
		return keep;
	}

	private boolean versionedFileExists(String fileName) {
		try {
			return (versionedFileSystem.isOnline() &&
				versionedFileSystem.getItem(parent.getPathname(), fileName) != null);
		}
		catch (IOException e) {
			// ignore
		}
		return false;
	}

	private void createKeepFile(DomainObject sourceObj, TaskMonitor monitor) {
		String keepName = name + ".keep";
		try {
			GhidraFileData keepFileData = parent.getFileData(keepName, false);
			if (keepFileData != null) {
				try {
					keepFileData.delete();
				}
				catch (IOException e) {
					Msg.error(this,
						"Failed to create keep file: failed to remove old keep file: " + keepName,
						e);
					return;
				}
			}
			keepName = getKeepName();
			Msg.info(this, "Creating old version keep file: " + keepName);
			parent.createFile(keepName, sourceObj, monitor);
		}
		catch (InvalidNameException e) {
			throw new AssertException("Unexpected error", e);
		}
		catch (CancelledException e) {
			// ignore
		}
		catch (IOException e) {
			Msg.error(this, "Failed to create keep file: " + keepName, e);
		}
	}

	/**
	 * Delete the entire database for this file, including any version files.
	 * @throws FileInUseException if this file is in-use / checked-out.
	 * @throws UserAccessException if the user does not have permission to delete the file.
	 * @throws IOException if an IO or access error occurs.
	 */
	void delete() throws IOException {
		synchronized (fileSystem) {
			if (fileSystem.isReadOnly()) {
				throw new ReadOnlyException("delete permitted within writeable project only");
			}
			checkInUse();
			if (folderItem != null && folderItem.isCheckedOut()) {
				throw new FileInUseException("Can not delete file while it is checked-out");
			}

			if (isHijacked()) {
				folderItem.delete(-1, ClientUtil.getUserName());
				parent.deleteLocalFolderIfEmpty();
				Msg.info(this, "Deleted local file, revealing hijacked file " + name);
			}
			else if (versionedFolderItem == null) {
				folderItem.delete(-1, ClientUtil.getUserName());
				Msg.info(this, "Deleted local file " + name);
			}
			else {
				versionedFolderItem.delete(-1, ClientUtil.getUserName());
				Msg.info(this, "Deleted versioned file " + name);
			}

			if (fileID != null && (folderItem == null || versionedFolderItem == null ||
				!fileID.equals(versionedFolderItem.getFileID()))) {
				removeAssociatedUserDataFile();
			}

			parent.fileChanged(name);
		}
	}

	/**
	 * Deletes a specific version of a file from the versioned filesystem.  
	 * @param version specific version to be deleted.  The version must either
	 * be the oldest or latest, or -1 which will attempt to remove all versions.
	 * When deleting the latest version, this method could take a long time
	 * to return since the previous version must be reconstructed within the
	 * versioned filesystem.
	 * @throws IOException if an IO error occurs, including the inability 
	 * to delete a version because this item is checked-out, the user does
	 * not have permission, or the specified version is not the oldest or
	 * latest.
	 */
	void delete(int version) throws IOException {
		synchronized (fileSystem) {
			if (fileSystem.isReadOnly()) {
				throw new ReadOnlyException(
					"delete(version) permitted within writeable project only");
			}
			if (versionedFolderItem == null) {
				throw new IOException(name + " is not versioned");
			}
			if (folderItem != null && folderItem.getCheckoutVersion() == version) {
				throw new FileInUseException(name + " version " + version + " is checked-out");
			}
			versionedFolderItem.delete(version, ClientUtil.getUserName());
		}
	}

	private void removeAssociatedUserDataFile() {
		try {
			ContentHandler<?> contentHandler = getContentHandler();
			if (contentHandler instanceof DBWithUserDataContentHandler) {
				FolderItem item = folderItem != null ? folderItem : versionedFolderItem;
				((DBWithUserDataContentHandler<?>) contentHandler).removeUserDataFile(item,
					parent.getUserFileSystem());
			}
		}
		catch (Exception e) {
			// ignore missing content handler
		}
	}

	/**
	 * Performs merge from current version of versioned file into local checked-out file. 
	 * @param okToUpgrade if true an upgrade will be performed if needed
	 * @param monitor task monitor
	 * @throws IOException if an IO or access error occurs
	 * @throws VersionException if unable to handle domain object version in versioned filesystem.
	 * If okToUpgrade was false, check exception to see if it can be upgraded
	 * @throws CancelledException if task monitor cancelled operation
	 */
	void merge(boolean okToUpgrade, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException("merge permitted within writeable project only");
		}
		if (parent.getProjectLocator().isTransient()) {
			throw new IOException("Merge not permitted for transient project");
		}
		if (!versionedFileSystem.isOnline()) {
			throw new NotConnectedException("Not connected to repository server");
		}
		if (!isCheckedOut()) {
			throw new IOException("File not checked out");
		}
		if (!(versionedFolderItem instanceof DatabaseItem)) {
			throw new IOException("unsupported operation");
		}
		if (folderItem.getCheckoutVersion() == versionedFolderItem.getCurrentVersion()) {
			throw new IOException("Versioned file has not been updated since checkout");
		}
		if (isChanged()) {
			throw new IOException("File has unsaved changes");
		}
		if (canRecover()) {
			throw new IOException("File recovery data exists");
		}
		verifyCheckout("merge");
		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}
		if (busy.getAndSet(true)) {
			throw new FileInUseException(name + " is busy");
		}

		FolderItem tmpItem = null;
		DomainObjectAdapterDB inUseDomainObj = null;
		projectData.mergeStarted();
		try {
			inUseDomainObj = getAndLockInUseDomainObjectForMergeUpdate("merge");

			if (!modifiedSinceCheckout()) {
				// Quick merge
				folderItem.updateCheckout(versionedFolderItem, true, monitor);
			}
			else {

				if (SystemUtilities.isInHeadlessMode()) {
					throw new IOException("Merge failed, merge is not supported in headless mode");
				}

				ContentHandler<?> contentHandler = getContentHandler();

				// Test versioned file for VersionException
				int mergeVer = versionedFolderItem.getCurrentVersion();
				if (!okToUpgrade) {
					// verify remote version can be opened without verion error
					DomainObject testObj = contentHandler.getReadOnlyObject(versionedFolderItem,
						mergeVer, false, this, monitor);
					testObj.release(this);
				}

				Msg.info(this, "Merging version " + mergeVer + " for " + name);

				// Copy current versioned item to temporary private item
				DatabaseItem databaseItem = (DatabaseItem) versionedFolderItem;
				BufferFile bufferFile = databaseItem.open(mergeVer);
				try {
					String tmpName = name + ".merge";
					tmpItem = fileSystem.createTemporaryDatabase(parent.getPathname(), tmpName,
						databaseItem.getFileID(), bufferFile, databaseItem.getContentType(), false,
						monitor);
				}
				catch (InvalidNameException e) {
					throw new AssertException("Unexpected error", e);
				}
				finally {
					bufferFile.dispose();
				}
				int coVer = folderItem.getCheckoutVersion();
				long checkoutId = folderItem.getCheckoutId();

				tmpItem.setCheckout(checkoutId, folderItem.isCheckedOutExclusive(), mergeVer, 0);

				DomainObject mergeObj = contentHandler.getDomainObject(tmpItem, null, -1,
					okToUpgrade, false, this, monitor);
				DomainObject sourceObj = null;
				DomainObject originalObj = null;
				DomainObject latestObj = null; // TODO: Is there some way to leverage the buffer file we already copied into tmpItem? Missing required change set
				try {
					sourceObj = contentHandler.getImmutableObject(folderItem, this,
						DomainFile.DEFAULT_VERSION, -1, monitor);
					originalObj = contentHandler.getImmutableObject(versionedFolderItem, this,
						coVer, -1, monitor);
					latestObj = contentHandler.getImmutableObject(versionedFolderItem, this,
						mergeVer, coVer, monitor);

					DomainObjectMergeManager mergeMgr =
						contentHandler.getMergeManager(mergeObj, sourceObj, originalObj, latestObj);

					if (!mergeMgr.merge(monitor)) {
						Msg.info(this, "Merge terminated for " + name);
						return; // error displayed by merge manager
					}

					mergeObj.save("Merge with version " + mergeVer, monitor);

					createKeepFile(sourceObj, monitor);
				}
				finally {
					release(mergeObj);
					release(sourceObj);
					release(originalObj);
					release(latestObj);
				}

				// Update folder item
				folderItem.updateCheckout(tmpItem, mergeVer);
				versionedFolderItem.updateCheckoutVersion(checkoutId, mergeVer,
					ClientUtil.getUserName());
				tmpItem = null;
				Msg.info(this, "Merge completed for " + name);

				if (inUseDomainObj != null) {
					contentHandler.resetDBSourceFile(folderItem, inUseDomainObj);
				}
			}

			if (inUseDomainObj != null) {
				inUseDomainObj.invalidate();
			}
		}
		finally {
			unlockDomainObject(inUseDomainObj);
			busy.set(false);
			try {
				if (tmpItem != null) {
					try {
						tmpItem.delete(-1, ClientUtil.getUserName());
					}
					catch (IOException e) {
						Msg.error(this, "IO error", e);
					}
				}
				parent.fileChanged(name);
				if (parent.visited()) {
					parent.refresh(false, true, null);
				}
			}
			finally {
				projectData.mergeEnded();
			}
		}

	}

	/**
	 * Move this file into the newParent folder.
	 * @param newParent new parent folder within the same project
	 * @return the newly relocated domain file (the original DomainFile object becomes invalid since it is immutable)
	 * @throws DuplicateFileException if a file with the same name 
	 * already exists in newParent folder.
	 * @throws FileInUseException if this file is in-use / checked-out.
	 * @throws IOException if an IO or access error occurs.
	 */
	GhidraFile moveTo(GhidraFolderData newParent) throws IOException {

		synchronized (fileSystem) {
			if (newParent.getLocalFileSystem() != fileSystem) {
				throw new IllegalArgumentException("moveTo permitted within same project only");
			}
			if (fileSystem.isReadOnly()) {
				throw new ReadOnlyException("moveTo permitted within writeable project only");
			}
			if (getParent().getPathname().equals(newParent.getPathname())) {
				throw new IllegalArgumentException("newParent must differ from current parent");
			}
			checkInUse();
			GhidraFolderData oldParent = parent;
			String oldName = name;
			String newName = newParent.getTargetName(name);
			try {
				if (isHijacked()) {
					fileSystem.moveItem(parent.getPathname(), name, newParent.getPathname(),
						newName);
					parent.fileChanged(name);
					newParent.fileChanged(newName);
					return newParent.getDomainFile(newName);
				}
				else if (versionedFolderItem == null) {
					if (!isCheckedOut()) {
						fileSystem.moveItem(parent.getPathname(), name, newParent.getPathname(),
							newName);
						folderItem = fileSystem.getItem(newParent.getPathname(), newName);
					}
					else {
						throw new FileInUseException(name + " is checked-out");
					}
				}
				else {
					versionedFileSystem.moveItem(parent.getPathname(), name,
						newParent.getPathname(), newName);
					versionedFolderItem =
						versionedFileSystem.getItem(newParent.getPathname(), newName);
				}
			}
			catch (InvalidNameException e) {
				throw new AssertException("Unexpected error", e);
			}

			parent = newParent;
			name = newName;

			oldParent.fileMoved(newParent, oldName, newName);

			return newParent.getDomainFile(newName);
		}
	}

	/**
	 * Determine if this file is a link file which corresponds to either a file or folder link.  
	 * The {@link DomainObject} referenced by a link-file may be opened using 
	 * {@link #getReadOnlyDomainObject(Object, int, TaskMonitor)}.  The 
	 * {@link #getDomainObject(Object, boolean, boolean, TaskMonitor)} method may also be used
	 * to obtain a read-only instance.  {@link #getImmutableDomainObject(Object, int, TaskMonitor)}
	 * use is not supported.
	 * The URL stored within the link-file may be read using {@link #getLinkFileURL()}.
	 * The content type (see {@link #getContentType()} of a link file will differ from that of the
	 * linked object (e.g., "LinkedProgram" vs "Program").
	 * @return true if link file else false for a normal domain file
	 */
	boolean isLinkFile() {
		synchronized (fileSystem) {
			try {
				return LinkHandler.class.isAssignableFrom(getContentHandler().getClass());
			}
			catch (IOException e) {
				return false;
			}
		}
	}

	/**
	 * Get URL associated with a link-file.  The URL returned may reference either a folder
	 * or a file within another project/repository.
	 * @return link-file URL or null if not a link-file
	 * @throws IOException if an IO error occurs
	 */
	URL getLinkFileURL() throws IOException {
		if (!isLinkFile()) {
			return null;
		}
		FolderItem item = folderItem != null ? folderItem : versionedFolderItem;
		return LinkHandler.getURL(item);
	}

	/**
	 * Determine if this file's content type supports linking.
	 * @return true if linking is supported allowing a link-file to be created which 
	 * references this file, else false.
	 */
	boolean isLinkingSupported() {
		synchronized (fileSystem) {
			try {
				return getContentHandler().getLinkHandler() != null;
			}
			catch (IOException e) {
				return false; // ignore error
			}
		}
	}

	/**
	 * Copy this file into the newParent folder as a link file.  Restrictions:
	 * <ul>
	 * <li>Specified newParent must reside within a different project since internal linking is
	 * not currently supported. </li>
	 * <li>Content type must support linking (see {@link #isLinkingSupported()}).</li>
	 * </ul>
	 * If this file is associated with a temporary transient project (i.e., not a locally 
	 * managed project) the generated link will refer to the remote file with a remote
	 * Ghidra URL, otherwise a local project storage path will be used.
	 * @param newParent new parent folder
	 * @return newly created domain file or null if content type does not support link use.
	 * @throws IOException if an IO or access error occurs.
	 */
	DomainFile copyToAsLink(GhidraFolderData newParent) throws IOException {
		synchronized (fileSystem) {
			LinkHandler<?> lh = getContentHandler().getLinkHandler();
			if (lh == null) {
				return null;
			}
			return newParent.copyAsLink(projectData, getPathname(), name, lh);
		}
	}

	/**
	 * Copy this file into the newParent folder as a private file.
	 * @param newParent new parent folder
	 * @param monitor task monitor
	 * @return newly created domain file
	 * @throws FileInUseException if this file is in-use / checked-out.
	 * @throws IOException if an IO or access error occurs.
	 * @throws CancelledException if task monitor cancelled operation.
	 */
	GhidraFile copyTo(GhidraFolderData newParent, TaskMonitor monitor)
			throws IOException, CancelledException {
		synchronized (fileSystem) {
			if (newParent.getLocalFileSystem().isReadOnly()) {
				throw new ReadOnlyException("copyVersionTo permitted to writeable project only");
			}
			FolderItem item = folderItem != null ? folderItem : versionedFolderItem;
			String pathname = newParent.getPathname();
			String contentType = item.getContentType();
			String targetName = newParent.getTargetName(name);
			String user = ClientUtil.getUserName();
			try {
				if (item instanceof DatabaseItem) {
					BufferFile bufferFile = ((DatabaseItem) item).open();
					try {
						newParent.getLocalFileSystem()
								.createDatabase(pathname, targetName, FileIDFactory.createFileID(),
									bufferFile, null, contentType, true, monitor, user);
					}
					finally {
						bufferFile.dispose();
					}
				}
				else if (item instanceof DataFileItem) {
					InputStream istream = ((DataFileItem) item).getInputStream();
					try {
						newParent.getLocalFileSystem()
								.createDataFile(pathname, targetName, istream, null, contentType,
									monitor);
					}
					finally {
						istream.close();
					}
				}
				else {
					throw new AssertException("Unknown Item in copyTo");
				}
			}
			catch (InvalidNameException e) {
				throw new AssertException("Unexpected error", e);
			}
			newParent.fileChanged(targetName);
			return newParent.getDomainFile(targetName);
		}
	}

	/**
	 * Copy a specific version of this file to the specified destFolder.
	 * @param version version to copy
	 * @param destFolder destination parent folder
	 * @param monitor task monitor
	 * @return the copied file
	 * @throws IOException if an IO or access error occurs.
	 * @throws CancelledException if task monitor cancelled operation.
	 */
	GhidraFile copyVersionTo(int version, GhidraFolderData destFolder, TaskMonitor monitor)
			throws IOException, CancelledException {
		synchronized (fileSystem) {
			if (destFolder.getLocalFileSystem().isReadOnly()) {
				throw new ReadOnlyException("copyVersionTo permitted to writeable project");
			}
			if (versionedFolderItem == null) {
				return null; // NOTE: versioned file system may be offline
			}
			if (!(versionedFolderItem instanceof DatabaseItem)) {
				throw new IOException("unsupported operation");
			}
			String pathname = destFolder.getPathname();
			String contentType = versionedFolderItem.getContentType();
			String targetName = destFolder.getTargetName(name + "_v" + version);
			String user = ClientUtil.getUserName();
			try {
				BufferFile bufferFile = ((DatabaseItem) versionedFolderItem).open(version);
				if (bufferFile == null) {
					return null; // TODO: not sure this can ever happen - IOException will probably occur instead
				}
				try {
					destFolder.getLocalFileSystem()
							.createDatabase(pathname, targetName, FileIDFactory.createFileID(),
								bufferFile, null, contentType, true, monitor, user);
				}
				finally {
					bufferFile.dispose();
				}
			}
			catch (InvalidNameException e) {
				throw new AssertException("Unexpected error", e);
			}
			destFolder.fileChanged(targetName);
			return destFolder.getDomainFile(targetName);
		}
	}

	/**
	 * Copy this file to make a private file if it is versioned. This method should be called
	 * only when a non shared project is being converted to a shared project.
	 * @param monitor task monitor
	 * @throws IOException if an IO error occurs
	 * @throws CancelledException if task is cancelled
	 */
	void convertToPrivateFile(TaskMonitor monitor) throws IOException, CancelledException {
		synchronized (fileSystem) {
			if (!(versionedFileSystem instanceof LocalFileSystem)) {
				throw new UnsupportedOperationException("not supported for project");
			}
			if (!isVersioned()) {
				return;
			}
			GhidraFolderData oldParent = getParent();
			if (isCheckedOut()) {
				// keep local changed file - discard revision information
				folderItem.clearCheckout();
				oldParent.fileChanged(name);
			}
			else {
				// copy this file to make a private copy
				GhidraFile df = copyTo(oldParent, monitor);
				versionedFolderItem.delete(-1, ClientUtil.getUserName());
				oldParent.fileChanged(name);
				try {
					df.setName(name);
				}
				catch (InvalidNameException e) {
					throw new AssertException("Unexpected error", e);
				}
			}
		}
	}

	/**
	 * Pack domain file into specified file.
	 * Specified file will be overwritten if it already exists.
	 * @param file destination file
	 * @param monitor the task monitor
	 * @throws IOException if there is an exception packing the file
	 * @throws CancelledException if monitor cancels operation
	 */
	void packFile(File file, TaskMonitor monitor) throws IOException, CancelledException {
		synchronized (fileSystem) {
			FolderItem item = folderItem != null ? folderItem : versionedFolderItem;
			item.output(file, FolderItem.LATEST_VERSION, monitor);
		}
	}

	/**
	 * Returns the length of this domain file.  This size is the minimum disk space
	 * used for storing this file, but does not account for additional storage space
	 * used to track changes, etc. 
	 * @return file length
	 * @throws IOException if IO or access error occurs
	 */
	long length() throws IOException {
		synchronized (fileSystem) {
			if (folderItem != null) {
				return folderItem.length();
			}
			if (versionedFolderItem != null) {
				return versionedFolderItem.length();
			}
			return 0;
		}
	}

	/**
	 * Returns an ordered map containing the metadata that has been associated with the 
	 * corresponding domain object. The map contains key,value pairs and are ordered by their 
	 * insertion order. 
	 * @return a map containing the metadata that has been associated with the corresponding domain 
	 * object.
	 */
	Map<String, String> getMetadata() {
		FolderItem item = (folderItem != null) ? folderItem : versionedFolderItem;
		return getMetadata(item);
	}

	/**
	 * Returns an ordered map containing the metadata stored within a specific {@link FolderItem}
	 * database. The map contains key,value pairs and are ordered by their insertion order. 
	 * @param item folder item whose metadata should be read
	 * @return a map containing the metadata that has been associated with the corresponding domain 
	 * object.  Map will be empty for a non-database item.
	 */
	static Map<String, String> getMetadata(FolderItem item) {
		if (!(item instanceof DatabaseItem databaseItem)) {
			return new HashMap<>();
		}
		ManagedBufferFile bf = null;
		DBHandle dbh = null;
		GenericDomainObjectDB genericDomainObj = null;
		try {
			bf = databaseItem.open();
			dbh = new DBHandle(bf);
			genericDomainObj = new GenericDomainObjectDB(dbh);
			return genericDomainObj.getMetadata();
		}
		catch (FileNotFoundException e) {
			// file has been deleted, just return an empty map.
		}
		catch (Field.UnsupportedFieldException e) {
			// file created with newer version of Ghidra
		}
		catch (IOException e) {
			Msg.error(GhidraFileData.class, "Read meta-data error", e);
		}
		finally {
			if (genericDomainObj != null) {
				genericDomainObj.release();
			}
			if (dbh != null) {
				dbh.close();
			}
			if (bf != null) {
				bf.dispose();
			}
		}
		return new HashMap<>();
	}

	@Override
	public String toString() {
		if (projectData == null) {
			return name + "(disposed)";
		}
		ProjectLocator projectLocator = projectData.getProjectLocator();
		if (projectLocator.isTransient()) {
			return projectData.getProjectLocator().getName() + getPathname();
		}
		return projectData.getProjectLocator().getName() + ":" + getPathname();
	}

	private static class GenericDomainObjectDB extends DomainObjectAdapterDB {

		protected GenericDomainObjectDB(DBHandle dbh) throws IOException {
			super(dbh, "Generic", 500, dbh);
			loadMetadata();
		}

		@Override
		public String getDescription() {
			return "Generic Database Domain Object";
		}

		@Override
		public boolean isChangeable() {
			return false;
		}

		public void release() {
			release(dbh);
		}
	}

}

/**
 * {@link VersionIcon} is the base icon for files which exist within the versioned filesystem.
 */
class VersionIcon implements Icon {

	private static Color VERSION_ICON_COLOR = new GColor("color.bg.icon.versioned");

	private static final int WIDTH = GhidraFileData.ICON_WIDTH;
	private static final int HEIGHT = GhidraFileData.ICON_HEIGHT;

	@Override
	public int getIconHeight() {
		return HEIGHT;
	}

	@Override
	public int getIconWidth() {
		return WIDTH;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		g.setColor(VERSION_ICON_COLOR);
		g.fillRect(x + 1, y + 1, WIDTH - 2, HEIGHT - 2);
		g.drawLine(x + 1, y, x + WIDTH - 2, y);
		g.drawLine(x + WIDTH - 1, y + 1, x + WIDTH - 1, y + HEIGHT - 2);
		g.drawLine(x + 1, y + HEIGHT - 1, x + WIDTH - 2, y + HEIGHT - 1);
		g.drawLine(x, y + 1, x, y + HEIGHT - 2);
	}
}

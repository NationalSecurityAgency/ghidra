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
import java.util.HashMap;
import java.util.Map;

import javax.swing.Icon;

import db.DBHandle;
import db.Field;
import db.buffers.*;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.NotConnectedException;
import ghidra.framework.model.*;
import ghidra.framework.store.*;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.framework.store.local.LocalFolderItem;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

public class GhidraFileData {

	private static boolean alwaysMerge = System.getProperty("ForceMerge") != null;

	public static final Icon UNSUPPORTED_FILE_ICON =
		ResourceManager.loadImage("images/unknownFile.gif");

	public static final Icon CHECKED_OUT_ICON = ResourceManager.loadImage("images/check.png");
	public static final Icon CHECKED_OUT_EXCLUSIVE_ICON =
		ResourceManager.loadImage("images/checkex.png");
	public static final Icon HIJACKED_ICON = ResourceManager.loadImage("images/small_hijack.gif");
	public static final Icon VERSION_ICON = new VersionIcon();
	public static final Icon READ_ONLY_ICON =
		ResourceManager.loadImage("images/user-busy.png", 10, 10);
	public static final Icon NOT_LATEST_CHECKED_OUT_ICON =
		ResourceManager.loadImage("images/checkNotLatest.gif");

	private ProjectFileManager fileManager;
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

	private volatile boolean busy = false;

// TODO: Many of the old methods assumed that the state was up-to-date due to
// refreshing ... we are relying on non-refreshed data to be dropped from cache map and no
// longer used.

	GhidraFileData(GhidraFolderData parent, String name) throws IOException {

		this.parent = parent;
		this.name = name;

		this.fileManager = parent.getProjectFileManager();
		this.fileSystem = parent.getLocalFileSystem();
		this.versionedFileSystem = parent.getVersionedFileSystem();
		this.listener = parent.getChangeListener();

		refresh();
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
		boolean fileIdWasNull = fileID == null;
		fileID = folderItem != null ? folderItem.getFileID() : versionedFolderItem.getFileID();

		return fileIdWasNull && fileID != null;
	}

	void statusChanged() throws IOException {
		statusChanged(false);
	}

	private void statusChanged(boolean fileIDset) throws IOException {
		icon = null;
		disabledIcon = null;
		fileIDset |= refresh();
		if (parent.visited()) {
			listener.domainFileStatusChanged(getDomainFile(), fileIDset);
		}
	}

	private void validateCheckout() throws IOException {
		if (fileSystem.isReadOnly() || !versionedFileSystem.isOnline()) {
			return;
		}
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

	void checkInUse() throws FileInUseException {
		synchronized (fileSystem) {
			if (busy || getOpenedDomainObject() != null) {
				throw new FileInUseException(name + " is in use");
			}
		}
	}

	boolean isBusy() {
		if (busy) {
			return true;
		}
		DomainObjectAdapter dobj = getOpenedDomainObject();
		return dobj != null && !dobj.canLock();
	}

	void dispose() {
		fileManager.removeFromIndex(fileID);
// NOTE: clearing the following can cause issues since there may be some residual
// activity/use which will get a NPE
//		parent = null;
//		fileManager = null;
//		listener = null;
	}

	String getFileID() {
		return fileID;
	}

	String getPathname() {
		String path = parent.getPathname();
		if (path.length() != FileSystem.SEPARATOR.length()) {
			path += FileSystem.SEPARATOR;
		}
		path += name;
		return path;
	}

	String getName() {
		return name;
	}

	GhidraFolderData getParent() {
		return parent;
	}

	GhidraFile getDomainFile() {
		return new GhidraFile(parent.getDomainFolder(), name);
	}

	/**
	 * Reassign a new file-ID to resolve file-ID conflict.
	 * Conflicts can occur as a result of a cancelled check-out.
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

	String getContentType() {
		synchronized (fileSystem) {
			FolderItem item = folderItem != null ? folderItem : versionedFolderItem;
			if (item == null) {
				return ContentHandler.MISSING_CONTENT;
			}
			String contentType = item.getContentType();
			return contentType != null ? contentType : ContentHandler.UNKNOWN_CONTENT;
		}
	}

	Class<? extends DomainObject> getDomainObjectClass() {
		synchronized (fileSystem) {
			FolderItem item = folderItem != null ? folderItem : versionedFolderItem;
			try {
				ContentHandler ch = DomainObjectAdapter.getContentHandler(item.getContentType());
				if (ch != null) {
					return ch.getDomainObjectClass();
				}
			}
			catch (IOException e) {
				// ignore missing content handler
			}
			return DomainObject.class;
		}
	}

	ChangeSet getChangesByOthersSinceCheckout() throws VersionException, IOException {
		synchronized (fileSystem) {
			if (versionedFolderItem != null && folderItem != null && folderItem.isCheckedOut()) {
				ContentHandler ch =
					DomainObjectAdapter.getContentHandler(folderItem.getContentType());
				return ch.getChangeSet(versionedFolderItem, folderItem.getCheckoutVersion(),
					versionedFolderItem.getCurrentVersion());
			}
			return null;
		}
	}

	private DomainObjectAdapter getOpenedDomainObject() {
		return fileManager.getOpenedDomainObject(getPathname());
	}

	DomainObject getDomainObject(Object consumer, boolean okToUpgrade, boolean okToRecover,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {
		FolderItem myFolderItem;
		ContentHandler ch;
		DomainObjectAdapter domainObj = null;
		synchronized (fileSystem) {
			if (fileSystem.isReadOnly()) {
				return getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);
			}
			domainObj = getOpenedDomainObject();
			if (domainObj != null) {
				if (!domainObj.addConsumer(consumer)) {
					domainObj = null;
					fileManager.clearDomainObject(getPathname());
				}
				else {
					return domainObj;
				}
			}
			if (folderItem == null) {
				ch = DomainObjectAdapter.getContentHandler(versionedFolderItem.getContentType());
				DomainObjectAdapter doa = ch.getReadOnlyObject(versionedFolderItem,
					DomainFile.DEFAULT_VERSION, true, consumer, monitor);
				doa.setChanged(false);
				DomainFileProxy proxy = new DomainFileProxy(name, parent.getPathname(), doa,
					DomainFile.DEFAULT_VERSION, fileID, parent.getProjectLocator());
				proxy.setLastModified(getLastModifiedTime());
				return doa;
			}
			ch = DomainObjectAdapter.getContentHandler(folderItem.getContentType());
			myFolderItem = folderItem;

			domainObj = ch.getDomainObject(myFolderItem, parent.getUserFileSystem(),
				FolderItem.DEFAULT_CHECKOUT_ID, okToUpgrade, okToRecover, consumer, monitor);
			fileManager.setDomainObject(getPathname(), domainObj);
		}

		// Set domain file for newly opened domain object
		// NOTE: Some domain object implementations may throw RuntimeExceptions
		// so cleanup is required in those cases
		try {
			domainObj.setDomainFile(getDomainFile());
		}
		catch (Exception e) {
			domainObj.release(consumer);
			fileManager.clearDomainObject(getPathname());
			// generate IOException
			Throwable cause = e.getCause();
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

	DomainObject getReadOnlyDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		synchronized (fileSystem) {
			FolderItem item =
				(folderItem != null && version == DomainFile.DEFAULT_VERSION) ? folderItem
						: versionedFolderItem;

			// this can happen when we are trying to load a version file from
			// a server to which we are not connected
			if (item == null) {
				return null;
			}

			ContentHandler ch = DomainObjectAdapter.getContentHandler(item.getContentType());
			DomainObjectAdapter doa = ch.getReadOnlyObject(item, version, true, consumer, monitor);
			doa.setChanged(false);

			DomainFileProxy proxy = new DomainFileProxy(name, getParent().getPathname(), doa,
				version, fileID, parent.getProjectLocator());
			proxy.setLastModified(getLastModifiedTime());
			return doa;
		}
	}

	DomainObject getImmutableDomainObject(Object consumer, int version, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		synchronized (fileSystem) {
			DomainObjectAdapter obj = null;
			if (versionedFolderItem == null ||
				(version == DomainFile.DEFAULT_VERSION && folderItem != null) || isHijacked()) {
				ContentHandler ch =
					DomainObjectAdapter.getContentHandler(folderItem.getContentType());
				obj = ch.getImmutableObject(folderItem, consumer, version, -1, monitor);
			}
			else {
				ContentHandler ch =
					DomainObjectAdapter.getContentHandler(versionedFolderItem.getContentType());
				obj = ch.getImmutableObject(versionedFolderItem, consumer, version, -1, monitor);
			}
			DomainFileProxy proxy = new DomainFileProxy(name, getParent().getPathname(), obj,
				version, fileID, parent.getProjectLocator());
			proxy.setLastModified(getLastModifiedTime());
			return obj;
		}
	}

	boolean canRecover() {
		synchronized (fileSystem) {
			DomainObjectAdapter dobj = getOpenedDomainObject();
			if (!fileSystem.isReadOnly() && folderItem != null && dobj == null) {
				return folderItem.canRecover();
			}
			return false;
		}
	}

	boolean takeRecoverySnapshot() throws IOException {
		DomainObjectAdapter dobj = fileManager.getOpenedDomainObject(getPathname());
		if (fileSystem.isReadOnly() || !(dobj instanceof DomainObjectAdapterDB) ||
			!dobj.isChanged()) {
			return true;
		}
		LockingTaskMonitor monitor = null;
		DomainObjectAdapterDB dbObjDB = (DomainObjectAdapterDB) dobj;
		synchronized (fileSystem) {
			if (busy) {
				return true;
			}
			busy = true;
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
			synchronized (fileSystem) {
				busy = false;
			}
			if (monitor != null) {
				monitor.releaseLock(); // releases lock
			}
		}
	}

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
			return UNSUPPORTED_FILE_ICON;
		}
		synchronized (fileSystem) {
			FolderItem item = folderItem != null ? folderItem : versionedFolderItem;
			if (versionedFolderItem != null) {
				MultiIcon multiIcon = new MultiIcon(VERSION_ICON, disabled);
				multiIcon.addIcon(getBaseIcon(item));
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
				return multiIcon;
			}
			else if (folderItem != null) {
				MultiIcon multiIcon = new MultiIcon(getBaseIcon(item), disabled);
				if (isReadOnly() && !fileSystem.isReadOnly()) {
					multiIcon.addIcon(new TranslateIcon(READ_ONLY_ICON, 6, 6));
				}
				if (isCheckedOut()) {
					if (isCheckedOutExclusive()) {
						multiIcon.addIcon(CHECKED_OUT_EXCLUSIVE_ICON);
					}
					else {
						multiIcon.addIcon(CHECKED_OUT_ICON);
					}
				}
				return multiIcon;
			}
		}
		return UNSUPPORTED_FILE_ICON;
	}

	private Icon getBaseIcon(FolderItem item) {
		try {
			ContentHandler ch = DomainObjectAdapter.getContentHandler(item.getContentType());
			if (ch != null) {
				return ch.getIcon();
			}
		}
		catch (IOException e) {
			// ignore missing content handler
		}
		return UNSUPPORTED_FILE_ICON;
	}

	boolean isChanged() {
		DomainObjectAdapter dobj = getOpenedDomainObject();
		return dobj != null && dobj.isChanged();
	}

	boolean isCheckedOut() {
		synchronized (fileSystem) {
			return folderItem != null && folderItem.isCheckedOut();
		}
	}

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

	boolean modifiedSinceCheckout() {
		synchronized (fileSystem) {
			return isCheckedOut() &&
				folderItem.getCurrentVersion() != folderItem.getLocalCheckoutVersion();
		}
	}

	boolean isReadOnly() {
		synchronized (fileSystem) {
			return folderItem != null && folderItem.isReadOnly();
		}
	}

	boolean isVersioned() {
		synchronized (fileSystem) {
			if (versionedFolderItem == null) {
				return isCheckedOut();
			}
			return !isHijacked();
		}
	}

	boolean isHijacked() {
		synchronized (fileSystem) {
			return folderItem != null && versionedFolderItem != null && !folderItem.isCheckedOut();
		}
	}

	boolean canAddToRepository() {
		synchronized (fileSystem) {
			try {
				return (!fileSystem.isReadOnly() && !versionedFileSystem.isReadOnly() &&
					folderItem != null && versionedFolderItem == null &&
					!folderItem.isCheckedOut() && isVersionControlSupported());
			}
			catch (IOException e) {
				return false;
			}
		}
	}

	boolean canCheckout() {
		synchronized (fileSystem) {
			try {
				return folderItem == null && !fileSystem.isReadOnly() &&
					!versionedFileSystem.isReadOnly();
			}
			catch (IOException e) {
				return false;
			}
		}
	}

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

	boolean isVersionControlSupported() {
		synchronized (fileSystem) {
			if (versionedFolderItem != null) {
				return true;
			}
			if (!(folderItem instanceof DatabaseItem)) {
				return false;
			}
			try {
				ContentHandler ch =
					DomainObjectAdapter.getContentHandler(folderItem.getContentType());
				return !ch.isPrivateContentType();
			}
			catch (IOException e) {
				// ignore missing content handler
			}
			return false;
		}
	}

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

	int getLatestVersion() {
		synchronized (fileSystem) {
			if (!isHijacked() && versionedFolderItem != null) {
				return versionedFolderItem.getCurrentVersion();
			}
			return 0;
		}
	}

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

	Version[] getVersionHistory() throws IOException {
		synchronized (fileSystem) {
			if (versionedFolderItem != null) {
				return versionedFolderItem.getVersions();
			}
			return null;
		}
	}

	void addToVersionControl(String comment, boolean keepCheckedOut, TaskMonitor monitor)
			throws IOException, CancelledException {
		DomainObjectAdapter oldDomainObj = null;
		synchronized (fileSystem) {
			if (!isVersionControlSupported()) {
				throw new AssertException("file type does supported version control");
			}
			if (versionedFolderItem != null) {
				throw new AssertException("file already versioned");
			}
			if (!versionedFileSystem.isOnline()) {
				throw new NotConnectedException("Not connected to repository server");
			}
			if (fileSystem.isReadOnly() || versionedFileSystem.isReadOnly()) {
				throw new ReadOnlyException(
					"addToVersionControl permitted within writeable project and repository only");
			}
			String parentPath = parent.getPathname();
			String user = ClientUtil.getUserName();
			try {
				if (folderItem instanceof DatabaseItem) {
					DatabaseItem databaseItem = (DatabaseItem) folderItem;
					BufferFile bufferFile = databaseItem.open();
					try {
						versionedFolderItem = versionedFileSystem.createDatabase(parentPath, name,
							folderItem.getFileID(), bufferFile, comment,
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
						versionedFolderItem = versionedFileSystem.createDataFile(parentPath, name,
							istream, comment, folderItem.getContentType(), monitor);
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

			oldDomainObj = getOpenedDomainObject();

			if (keepCheckedOut) {
				boolean exclusive = !versionedFileSystem.isShared();
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
				if (oldDomainObj == null) {
					try {
						folderItem.delete(-1, ClientUtil.getUserName());
						folderItem = null;
					}
					catch (FileInUseException e1) {
						// Ignore - should result in Hijacked file
					}
				}
			}
			if (oldDomainObj != null) {

				// TODO: Develop way to re-use and re-init domain object instead of a switch-a-roo approach

				fileManager.clearDomainObject(getPathname());

				oldDomainObj.setDomainFile(new DomainFileProxy("~" + name, oldDomainObj));
				oldDomainObj.setTemporary(true);
			}
		}
		if (oldDomainObj != null) {
			// Complete re-open of file
			DomainFile df = getDomainFile();
			listener.domainFileObjectClosed(df, oldDomainObj);
			listener.domainFileObjectReplaced(df, oldDomainObj);
		}
		if (!keepCheckedOut) {
			parent.deleteLocalFolderIfEmpty();
		}
		statusChanged();
	}

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
				versionedFolderItem.checkout(checkoutType, user, ItemCheckoutStatus.getProjectPath(
					projectLocator.toString(), projectLocator.isTransient()));
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

		monitor.checkCanceled();
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
// TODO: assumes folderItem is local - should probably defer createNewVersion to folderItem if possible (requires refactor)
				srcFile = (LocalManagedBufferFile) ((DatabaseItem) folderItem).open();
			}

			String comment = checkinHandler.getComment();
			if (checkinHandler.createKeepFile()) {
				DomainObject sourceObj = null;
				try {
					ContentHandler ch =
						DomainObjectAdapter.getContentHandler(folderItem.getContentType());
					sourceObj = ch.getImmutableObject(folderItem, this, DomainFile.DEFAULT_VERSION,
						-1, monitor);
					createKeepFile(sourceObj, monitor);
				}
				catch (VersionException e) {
					// ignore - unable to create keep file
				}
				finally {
					if (sourceObj != null) {
						sourceObj.release(this);
					}
				}
			}
			monitor.checkCanceled();
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
	 * Verify that current user is the checkout user for this file
	 * @param caseName name of user case (e.g., checkin)
	 * @return true if server/repository will permit current user to checkin,
	 * or update checkout version of current file.  (i.e., server login matches
	 * user name used at time of initial checkout)
	 */
	private void verifyRepoUser(String caseName) throws IOException {
		if (versionedFileSystem instanceof LocalFileSystem) {
			return; // rely on local project ownership
		}
		String repoUserName = versionedFileSystem.getUserName();
		if (repoUserName == null) {
			throw new IOException("File " + caseName + " not permitted (not connected)");
		}
		ItemCheckoutStatus checkoutStatus = getCheckoutStatus();
		if (checkoutStatus == null) {
			throw new IOException("File not checked out");
		}
		String checkoutUserName = checkoutStatus.getUser();
		if (!repoUserName.equals(checkoutUserName)) {
			throw new IOException("File " + caseName + " not permitted - checkout user '" +
				checkoutUserName + "' differs from repository user '" + repoUserName + "'");
		}
	}

	void checkin(CheckinHandler checkinHandler, boolean okToUpgrade, TaskMonitor monitor)
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
		verifyRepoUser("checkin");
		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}
		synchronized (fileSystem) {
			if (busy) {
				throw new FileInUseException(name + " is busy");
			}
			busy = true;
		}
		try {
			boolean quickCheckin = alwaysMerge ? false : quickCheckin(checkinHandler, monitor);

			if (!quickCheckin) {

				if (SystemUtilities.isInHeadlessMode()) {
					throw new IOException(
						"Checkin failed, file requires merge which is not supported in headless mode");
				}

				Msg.info(this, "Checkin with merge for " + name);

				ContentHandler ch =
					DomainObjectAdapter.getContentHandler(folderItem.getContentType());

				DomainObjectAdapter checkinObj = ch.getDomainObject(versionedFolderItem, null,
					folderItem.getCheckoutId(), okToUpgrade, false, this, monitor);
				checkinObj.setDomainFile(new DomainFileProxy(name, getParent().getPathname(),
					checkinObj, versionedFolderItem.getCurrentVersion() + 1, fileID,
					parent.getProjectLocator()));

				DomainObject sourceObj = null;
				DomainObject originalObj = null;
				DomainObject latestObj = null;
				try {
					synchronized (fileSystem) {
						int coVer = folderItem.getCheckoutVersion();
						sourceObj = ch.getImmutableObject(folderItem, this,
							DomainFile.DEFAULT_VERSION, -1, monitor);
						originalObj =
							ch.getImmutableObject(versionedFolderItem, this, coVer, -1, monitor);
						latestObj = ch.getImmutableObject(versionedFolderItem, this,
							DomainFile.DEFAULT_VERSION, coVer, monitor);
					}
					DomainObjectMergeManager mergeMgr =
						ch.getMergeManager(checkinObj, sourceObj, originalObj, latestObj);

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
					if (sourceObj != null) {
						sourceObj.release(this);
					}
					if (originalObj != null) {
						originalObj.release(this);
					}
					if (latestObj != null) {
						latestObj.release(this);
					}
				}
			}

			DomainObjectAdapter oldDomainObj = null;

			FolderItem oldLocalItem = null;
			boolean keepCheckedOut = checkinHandler.keepCheckedOut();

			synchronized (fileSystem) {

				oldDomainObj = getOpenedDomainObject();

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
							try {
								undoCheckout(false, true);
							}
							catch (IOException e) {
								Msg.error(this, "Undo checkout error", e);
							}
						}
					}
				}
				else {
					if (oldDomainObj != null) {
						oldLocalItem = folderItem;
						folderItem = null;
					}
					else {
						undoCheckout(false, true);
					}
				}
				if (oldDomainObj != null) {

					// TODO: Develop way to re-use and re-init domain object instead of a switch-a-roo approach

					fileManager.clearDomainObject(getPathname());

					oldDomainObj.setDomainFile(new DomainFileProxy(name, parent.getPathname(),
						oldDomainObj, -2, fileID, parent.getProjectLocator())); // invalid version (-2) specified to avoid file match
					oldDomainObj.setTemporary(true);
				}
			}

			if (oldDomainObj != null) {
				// complete re-open of domain file
				DomainFile df = getDomainFile();
				listener.domainFileObjectClosed(df, oldDomainObj);
				listener.domainFileObjectReplaced(df, oldDomainObj);
			}

			if (oldLocalItem != null) {
				synchronized (fileSystem) {
					// Undo checkout of old item - this will fail on Windows if item is open
					long checkoutId = oldLocalItem.getCheckoutId();
					oldLocalItem.delete(-1, ClientUtil.getUserName());
					versionedFolderItem.terminateCheckout(checkoutId, true);
				}
			}
		}
		finally {
			busy = false;
			parent.deleteLocalFolderIfEmpty();
			parent.fileChanged(name);
		}

	}

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

	void undoCheckout(boolean keep, boolean inUseOK) throws IOException {
		synchronized (fileSystem) {
			if (fileSystem.isReadOnly()) {
				throw new ReadOnlyException("undoCheckout permitted within writeable project only");
			}
			if (!inUseOK) {
				checkInUse();
			}
			if (!versionedFileSystem.isOnline()) {
				throw new NotConnectedException("Not connected to repository server");
			}
			if (!isCheckedOut()) {
				throw new IOException("File not checked out");
			}
			verifyRepoUser("undo-checkout");
			long checkoutId = folderItem.getCheckoutId();
			String keepName = getKeepName();
			versionedFolderItem.terminateCheckout(checkoutId, true);
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

	private void createKeepFile(DomainObject oldDomainObj, TaskMonitor monitor) {
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
			parent.createFile(keepName, oldDomainObj, monitor);
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
			FolderItem item = folderItem != null ? folderItem : versionedFolderItem;
			ContentHandler ch = DomainObjectAdapter.getContentHandler(item.getContentType());
			ch.removeUserDataFile(item, parent.getUserFileSystem());
		}
		catch (Exception e) {
			// ignore missing content handler
		}
	}

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
		verifyRepoUser("merge");
		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}
		synchronized (fileSystem) {
			if (busy) {
				throw new FileInUseException(name + " is busy");
			}
			busy = true;
		}

		FolderItem tmpItem = null;
		try {
			if (!modifiedSinceCheckout()) {
				// Quick merge
				folderItem.updateCheckout(versionedFolderItem, true, monitor);
			}
			else {

				if (SystemUtilities.isInHeadlessMode()) {
					throw new IOException(
						"Merge failed, file merge is not supported in headless mode");
				}

				ContentHandler ch =
					DomainObjectAdapter.getContentHandler(folderItem.getContentType());

				// Test versioned file for VersionException
				int mergeVer = versionedFolderItem.getCurrentVersion();
				if (!okToUpgrade) {
					DomainObject testObj =
						ch.getReadOnlyObject(versionedFolderItem, mergeVer, false, this, monitor);
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

				DomainObject mergeObj =
					ch.getDomainObject(tmpItem, null, -1, okToUpgrade, false, this, monitor);
				DomainObject sourceObj = null;
				DomainObject originalObj = null;
				DomainObject latestObj = null; // TODO: Is there some way to leverage the buffer file we already copied into tmpItem? Missing required change set
				try {
					sourceObj = ch.getImmutableObject(folderItem, this, DomainFile.DEFAULT_VERSION,
						-1, monitor);
					originalObj =
						ch.getImmutableObject(versionedFolderItem, this, coVer, -1, monitor);
					latestObj =
						ch.getImmutableObject(versionedFolderItem, this, mergeVer, coVer, monitor);

					DomainObjectMergeManager mergeMgr =
						ch.getMergeManager(mergeObj, sourceObj, originalObj, latestObj);

					if (!mergeMgr.merge(monitor)) {
						Msg.info(this, "Merge terminated for " + name);
						return; // error displayed by merge manager
					}

					mergeObj.save("Merge with version " + mergeVer, monitor);
					createKeepFile(sourceObj, monitor);
				}
				finally {
					mergeObj.release(this);
					if (sourceObj != null) {
						sourceObj.release(this);
					}
					if (originalObj != null) {
						originalObj.release(this);
					}
					if (latestObj != null) {
						latestObj.release(this);
					}
				}

				// Update folder item
				folderItem.updateCheckout(tmpItem, mergeVer);
				versionedFolderItem.updateCheckoutVersion(checkoutId, mergeVer,
					ClientUtil.getUserName());
				tmpItem = null;
				Msg.info(this, "Merge completed for " + name);
			}

			DomainObjectAdapter oldDomainObj = null;

			// TODO: Develop way to re-use and re-init domain object instead of a switch-a-roo approach

			synchronized (fileSystem) {
				oldDomainObj = getOpenedDomainObject();
				if (oldDomainObj != null) {
					fileManager.clearDomainObject(getPathname());
					oldDomainObj.setDomainFile(new DomainFileProxy("~" + name, oldDomainObj));
					oldDomainObj.setTemporary(true);
				}
			}

			if (oldDomainObj != null) {
				// Complete re-open of file
				DomainFile df = getDomainFile();
				listener.domainFileObjectClosed(df, oldDomainObj);
				listener.domainFileObjectReplaced(df, oldDomainObj);
			}
		}
		finally {
			busy = false;
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

	}

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
			String newName = getTargetName(name, newParent);
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

	private String getTargetName(String preferredName, GhidraFolderData newParent)
			throws IOException {
		String newName = preferredName;
		int i = 1;
		while (newParent.getFileData(newName, false) != null) {
			newName = preferredName + "." + i;
			i++;
		}
		return newName;
	}

	GhidraFile copyTo(GhidraFolderData newParentData, TaskMonitor monitor)
			throws IOException, CancelledException {
		synchronized (fileSystem) {
			if (newParentData.getLocalFileSystem().isReadOnly()) {
				throw new ReadOnlyException("copyVersionTo permitted to writeable project only");
			}
			FolderItem item = folderItem != null ? folderItem : versionedFolderItem;
			String pathname = newParentData.getPathname();
			String contentType = item.getContentType();
			String targetName = getTargetName(name, newParentData);
			String user = ClientUtil.getUserName();
			try {
				if (item instanceof DatabaseItem) {
					BufferFile bufferFile = ((DatabaseItem) item).open();
					try {
						newParentData.getLocalFileSystem().createDatabase(pathname, targetName,
							FileIDFactory.createFileID(), bufferFile, null, contentType, true,
							monitor, user);
					}
					finally {
						bufferFile.dispose();
					}
				}
				else if (item instanceof DataFileItem) {
					InputStream istream = ((DataFileItem) item).getInputStream();
					try {
						newParentData.getLocalFileSystem().createDataFile(pathname, targetName,
							istream, null, contentType, monitor);
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
			newParentData.fileChanged(targetName);
			return newParentData.getDomainFile(targetName);
		}
	}

	GhidraFile copyVersionTo(int version, GhidraFolderData destFolderData, TaskMonitor monitor)
			throws IOException, CancelledException {
		synchronized (fileSystem) {
			if (destFolderData.getLocalFileSystem().isReadOnly()) {
				throw new ReadOnlyException("copyVersionTo permitted to writeable project");
			}
			if (versionedFolderItem == null) {
				return null; // NOTE: versioned file system may be offline
			}
			if (!(versionedFolderItem instanceof DatabaseItem)) {
				throw new IOException("unsupported operation");
			}
			String pathname = destFolderData.getPathname();
			String contentType = versionedFolderItem.getContentType();
			String targetName = getTargetName(name + "_v" + version, destFolderData);
			String user = ClientUtil.getUserName();
			try {
				BufferFile bufferFile = ((DatabaseItem) versionedFolderItem).open(version);
				if (bufferFile == null) {
					return null; // TODO: not sure this can ever happen - IOException will probably occur instead
				}
				try {
					destFolderData.getLocalFileSystem().createDatabase(pathname, targetName,
						FileIDFactory.createFileID(), bufferFile, null, contentType, true, monitor,
						user);
				}
				finally {
					bufferFile.dispose();
				}
			}
			catch (InvalidNameException e) {
				throw new AssertException("Unexpected error", e);
			}
			destFolderData.fileChanged(targetName);
			return destFolderData.getDomainFile(targetName);
		}
	}

	/**
	 * Copy this file to make a private file if it is versioned. This method should be called
	 * only when a non shared project is being converted to a shared project.
	 * @throws IOException
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

	void packFile(File file, TaskMonitor monitor) throws IOException, CancelledException {
		synchronized (fileSystem) {
			FolderItem item = folderItem != null ? folderItem : versionedFolderItem;
			item.output(file, FolderItem.LATEST_VERSION, monitor);
		}
	}

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

	Map<String, String> getMetadata() {
		FolderItem item = (folderItem != null) ? folderItem : versionedFolderItem;

		GenericDomainObjectDB genericDomainObj = null;
		try {
			if (item instanceof DatabaseItem) {
				DatabaseItem databaseItem = (DatabaseItem) item;
				BufferFile bf = databaseItem.open();
				DBHandle dbh = new DBHandle(bf);
				genericDomainObj = new GenericDomainObjectDB(dbh);
				return genericDomainObj.getMetadata();
			}
		}
		catch (FileNotFoundException e) {
			// file has been deleted, just return an empty map.
		}
		catch (Field.UnsupportedFieldException e) {
			// file created with newer version of Ghidra
		}
		catch (IOException e) {
			Msg.error(this, "Read meta-data error", e);
		}
		finally {
			if (genericDomainObj != null) {
				genericDomainObj.release();
			}
		}
		return new HashMap<>();
	}

	@Override
	public String toString() {
		if (fileManager == null) {
			return name + "(disposed)";
		}
		return fileManager.getProjectLocator().getName() + ":" + getPathname();
	}

	private class GenericDomainObjectDB extends DomainObjectAdapterDB {

		protected GenericDomainObjectDB(DBHandle dbh) throws IOException {
			super(dbh, "Generic", 500, 1000, GhidraFileData.this);
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
			release(GhidraFileData.this);
		}
	}

}

class VersionIcon implements Icon {

	private static Color VERSION_ICON_COLOR_DARK = new Color(0x82, 0x82, 0xff);
	private static Color VERSION_ICON_COLOR_LIGHT = new Color(0x9f, 0x9f, 0xff);

	private static final int WIDTH = 18;
	private static final int HEIGHT = 17;

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
		g.setColor(VERSION_ICON_COLOR_LIGHT);
		g.fillRect(x + 1, y + 1, WIDTH - 2, HEIGHT - 2);
		g.setColor(VERSION_ICON_COLOR_DARK);
		g.drawLine(x + 1, y, x + WIDTH - 2, y);
		g.drawLine(x + WIDTH - 1, y + 1, x + WIDTH - 1, y + HEIGHT - 2);
		g.drawLine(x + 1, y + HEIGHT - 1, x + WIDTH - 2, y + HEIGHT - 1);
		g.drawLine(x, y + 1, x, y + HEIGHT - 2);
	}
}

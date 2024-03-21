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
package ghidra.feature.vt.api.db;

import java.io.IOException;

import javax.swing.Icon;

import db.DBHandle;
import db.buffers.BufferFile;
import db.buffers.LocalManagedBufferFile;
import generic.theme.GIcon;
import ghidra.framework.data.*;
import ghidra.framework.model.ChangeSet;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.*;
import ghidra.framework.store.local.LocalDatabaseItem;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class VTSessionContentHandler extends DBContentHandler<VTSessionDB> {

	public static final String CONTENT_TYPE = "VersionTracking";

	private static final Icon ICON = new GIcon("icon.version.tracking.session.content.type");

	@Override
	public long createFile(FileSystem fs, FileSystem userfs, String path, String name,
			DomainObject domainObject, TaskMonitor monitor)
			throws IOException, InvalidNameException, CancelledException {

		if (!(domainObject instanceof VTSessionDB)) {
			throw new IOException(
				"Unsupported domain object: " + domainObject.getClass().getName());
		}
		return createFile((VTSessionDB) domainObject, CONTENT_TYPE, fs, path, name, monitor);
	}

	@Override
	public ChangeSet getChangeSet(FolderItem versionedFolderItem, int olderVersion,
			int newerVersion) throws VersionException, IOException {
		return null;
	}

	@Override
	public String getContentType() {
		return CONTENT_TYPE;
	}

	@Override
	public String getContentTypeDisplayString() {
		return "Version Tracking Session";
	}

	@Override
	public String getDefaultToolName() {
		return "Version Tracking";
	}

	private void checkContentAndExclusiveCheckout(FolderItem item) throws IOException {
		String contentType = item.getContentType();
		if (!contentType.equals(CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}

		// NOTE: item.isVersioned indicates that item is located on versioned filesystem
		// and is not checked-out, otheriwse assume item in local filesystem and must
		// ensure if any checkout is exclusive.
		if (item.isVersioned() || (item.isCheckedOut() && !item.isCheckedOutExclusive())) {
			throw new IOException(
				"Unsupported VT Session use: session file must be checked-out exclusive");
		}
	}

	@Override
	public VTSessionDB getDomainObject(FolderItem item, FileSystem userfs, long checkoutId,
			boolean okToUpgrade, boolean okToRecover, Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException {

		checkContentAndExclusiveCheckout(item);

		if (item.isReadOnly()) {
			throw new ReadOnlyException("VT Session file is set read-only which prevents its use");
		}

		try {
			DatabaseItem dbItem = (DatabaseItem) item;
			BufferFile bf = dbItem.openForUpdate(checkoutId);
			DBHandle dbh = new DBHandle(bf, okToRecover, monitor);
			boolean success = false;
			try {
				// NOTE: Always open with DB upgrade enabled
				VTSessionDB db = new VTSessionDB(dbh, monitor, consumer);
				success = true;
				return db;
			}
			finally {
				if (!success) {
					dbh.close();
				}
			}
		}
		catch (VersionException | IOException | CancelledException e) {
			throw e;
		}
		catch (Throwable t) {
			Msg.error(this, "getDomainObject failed", t);
			String msg = t.getMessage();
			if (msg == null) {
				msg = t.toString();
			}
			throw new IOException("Open failed: " + msg, t);
		}

	}

	@Override
	public Class<VTSessionDB> getDomainObjectClass() {
		return VTSessionDB.class;
	}

	@Override
	public Icon getIcon() {
		return ICON;
	}

	@Override
	public VTSessionDB getImmutableObject(FolderItem item, Object consumer, int version,
			int minChangeVersion, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException {

		return getReadOnlyObject(item, -1, false, consumer, monitor);
	}

	@Override
	public DomainObjectMergeManager getMergeManager(DomainObject resultsObj, DomainObject sourceObj,
			DomainObject originalObj, DomainObject latestObj) {

		return null;
	}

	@Override
	public VTSessionDB getReadOnlyObject(FolderItem item, int version, boolean okToUpgrade,
			Object consumer, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {

		checkContentAndExclusiveCheckout(item);

		throw new ReadOnlyException("VT Session does not support read-only use");
	}

	@Override
	public boolean isPrivateContentType() {
		return false;
	}

	@Override
	public boolean canResetDBSourceFile() {
		return true;
	}

	@Override
	public void resetDBSourceFile(FolderItem item, DomainObjectAdapterDB domainObj)
			throws IOException {
		if (!(item instanceof LocalDatabaseItem dbItem) ||
			!(domainObj instanceof VTSessionDB vtSession)) {
			throw new IllegalArgumentException("LocalDatabaseItem and VTSessionDB required");
		}
		LocalManagedBufferFile bf = dbItem.openForUpdate(FolderItem.DEFAULT_CHECKOUT_ID);
		vtSession.getDBHandle().setDBVersionedSourceFile(bf);
	}

}

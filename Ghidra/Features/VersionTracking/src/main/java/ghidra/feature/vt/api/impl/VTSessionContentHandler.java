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
package ghidra.feature.vt.api.impl;

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.framework.data.*;
import ghidra.framework.model.ChangeSet;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.*;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import resources.ResourceManager;
import db.DBHandle;
import db.OpenMode;
import db.buffers.BufferFile;

public class VTSessionContentHandler extends DBContentHandler {
	private static ImageIcon ICON = ResourceManager.getScaledIcon(
		ResourceManager.loadImage("images/start-here_16.png"), 16, 16);

	public final static String CONTENT_TYPE = "VersionTracking";

	@Override
	public long createFile(FileSystem fs, FileSystem userfs, String path, String name,
			DomainObject domainObject, TaskMonitor monitor) throws IOException,
			InvalidNameException, CancelledException {

		if (!(domainObject instanceof VTSessionDB)) {
			throw new IOException("Unsupported domain object: " + domainObject.getClass().getName());
		}
		return createFile((VTSessionDB) domainObject, CONTENT_TYPE, fs, path, name, monitor);

	}

	@Override
	public ChangeSet getChangeSet(FolderItem versionedFolderItem, int olderVersion, int newerVersion)
			throws VersionException, IOException {
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

	@Override
	public DomainObjectAdapter getDomainObject(FolderItem item, FileSystem userfs, long checkoutId,
			boolean okToUpgrade, boolean okToRecover, Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException {

		String contentType = item.getContentType();
		if (!contentType.equals(CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		try {
			DatabaseItem dbItem = (DatabaseItem) item;
			BufferFile bf = dbItem.openForUpdate(checkoutId);
			DBHandle dbh = new DBHandle(bf, okToRecover, monitor);
			boolean success = false;
			try {
				VTSessionDB db = VTSessionDB.getVTSession(dbh, OpenMode.UPGRADE, consumer, monitor);
				success = true;
				return db;
			}
			finally {
				if (!success) {
					dbh.close();
				}
			}
		}
		catch (VersionException e) {
			throw e;
		}
		catch (IOException e) {
			throw e;
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Throwable t) {
			Msg.error(this, "getDomainObject failed", t);
			String msg = t.getMessage();
			if (msg == null) {
				msg = t.toString();
			}
			throw new IOException("Open failed: " + msg);
		}

	}

	@Override
	public Class<? extends DomainObject> getDomainObjectClass() {
		return VTSessionDB.class;
	}

	@Override
	public Icon getIcon() {
		return ICON;
	}

	@Override
	public DomainObjectAdapter getImmutableObject(FolderItem item, Object consumer, int version,
			int minChangeVersion, TaskMonitor monitor) throws IOException, CancelledException,
			VersionException {

		String contentType = item.getContentType();
		if (!contentType.equals(CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		return getReadOnlyObject(item, -1, false, consumer, monitor);

	}

	@Override
	public DomainObjectMergeManager getMergeManager(DomainObject resultsObj,
			DomainObject sourceObj, DomainObject originalObj, DomainObject latestObj) {

		return null;
	}

	@Override
	public DomainObjectAdapter getReadOnlyObject(FolderItem item, int version, boolean okToUpgrade,
			Object consumer, TaskMonitor monitor) throws IOException, VersionException,
			CancelledException {

		String contentType = item.getContentType();
		if (contentType != null && !contentType.equals(CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		try {
			DatabaseItem dbItem = (DatabaseItem) item;
			BufferFile bf = dbItem.open();
			DBHandle dbh = new DBHandle(bf);
			boolean success = false;
			try {
				VTSessionDB manager =
					VTSessionDB.getVTSession(dbh, OpenMode.READ_ONLY, consumer, monitor);
				success = true;
				return manager;
			}
			finally {
				if (!success) {
					dbh.close();
				}
			}
		}
		catch (IOException e) {
			throw e;
		}
		catch (Throwable t) {
			Msg.error(this, "getImmutableObject failed", t);
			String msg = t.getMessage();
			if (msg == null) {
				msg = t.toString();
			}
			throw new IOException("Open failed: " + msg);
		}
	}

	@Override
	public boolean isPrivateContentType() {
		return true;
	}

}

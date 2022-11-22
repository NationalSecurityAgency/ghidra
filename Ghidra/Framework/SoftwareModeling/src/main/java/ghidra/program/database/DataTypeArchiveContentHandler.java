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
package ghidra.program.database;

import java.io.IOException;

import javax.swing.Icon;

import db.DBConstants;
import db.DBHandle;
import db.buffers.BufferFile;
import db.buffers.ManagedBufferFile;
import generic.theme.GIcon;
import ghidra.framework.data.DBContentHandler;
import ghidra.framework.data.DomainObjectMergeManager;
import ghidra.framework.model.ChangeSet;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.*;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>DataTypeArchiveContentHandler</code> converts between DataTypeArchive instantiations
 * and FolderItem storage.  This class also produces the appropriate Icon for 
 * DataTypeArchive files.
 */
public class DataTypeArchiveContentHandler extends DBContentHandler<DataTypeArchiveDB> {

	static Icon DATA_TYPE_ARCHIVE_ICON = new GIcon("icon.content.handler.archive.dt");

	public final static String DATA_TYPE_ARCHIVE_CONTENT_TYPE = "Archive";

	final static Class<DataTypeArchiveDB> DATA_TYPE_ARCHIVE_DOMAIN_OBJECT_CLASS =
		DataTypeArchiveDB.class;
	final static String DATA_TYPE_ARCHIVE_CONTENT_DEFAULT_TOOL = "CodeBrowser";

	private static final DataTypeArchiveLinkContentHandler linkHandler =
		new DataTypeArchiveLinkContentHandler();

	@Override
	public long createFile(FileSystem fs, FileSystem userfs, String path, String name,
			DomainObject obj, TaskMonitor monitor)
			throws IOException, InvalidNameException, CancelledException {

		if (!(obj instanceof DataTypeArchiveDB)) {
			throw new IOException("Unsupported domain object: " + obj.getClass().getName());
		}
		return createFile((DataTypeArchiveDB) obj, DATA_TYPE_ARCHIVE_CONTENT_TYPE, fs, path, name,
			monitor);
	}

	@Override
	public DataTypeArchiveDB getImmutableObject(FolderItem item, Object consumer, int version,
			int minChangeVersion, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		String contentType = item.getContentType();
		if (contentType != null && !contentType.equals(DATA_TYPE_ARCHIVE_CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		DatabaseItem dbItem = (DatabaseItem) item;
		ManagedBufferFile bf = null;
		DBHandle dbh = null;
		DataTypeArchiveDB dataTypeArchive = null;
		boolean success = false;
		try {
			bf = dbItem.open(version, minChangeVersion);
			dbh = new DBHandle(bf);
			int openMode = DBConstants.READ_ONLY;
			dataTypeArchive = new DataTypeArchiveDB(dbh, openMode, monitor, consumer);
			getDataTypeArchiveChangeSet(dataTypeArchive, bf);
			success = true;
			return dataTypeArchive;
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
			Msg.error(this, "getImmutableObject failed", t);
			String msg = t.getMessage();
			if (msg == null) {
				msg = t.toString();
			}
			throw new IOException("Open failed: " + msg);
		}
		finally {
			if (!success) {
				if (dataTypeArchive != null) {
					dataTypeArchive.release(consumer);
				}
				if (dbh != null) {
					dbh.close();
				}
				if (bf != null) {
					bf.dispose();
				}
			}
		}
	}

	@Override
	public DataTypeArchiveDB getReadOnlyObject(FolderItem item, int version, boolean okToUpgrade,
			Object consumer, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {

		String contentType = item.getContentType();
		if (contentType != null && !contentType.equals(DATA_TYPE_ARCHIVE_CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		DatabaseItem dbItem = (DatabaseItem) item;
		ManagedBufferFile bf = null;
		DBHandle dbh = null;
		DataTypeArchiveDB dataTypeArchive = null;
		boolean success = false;
		try {
			bf = dbItem.open(version);
			dbh = new DBHandle(bf);
			int openMode = okToUpgrade ? DBConstants.UPGRADE : DBConstants.UPDATE;
			dataTypeArchive = new DataTypeArchiveDB(dbh, openMode, monitor, consumer);
			getDataTypeArchiveChangeSet(dataTypeArchive, bf);
			success = true;
			return dataTypeArchive;
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
			Msg.error(this, "getReadOnlyObject failed", t);
			String msg = t.getMessage();
			if (msg == null) {
				msg = t.toString();
			}
			throw new IOException("Open failed: " + msg);
		}
		finally {
			if (!success) {
				if (dataTypeArchive != null) {
					dataTypeArchive.release(consumer);
				}
				if (dbh != null) {
					dbh.close();
				}
				if (bf != null) {
					bf.dispose();
				}
			}
		}
	}

	@Override
	public DataTypeArchiveDB getDomainObject(FolderItem item, FileSystem userfs, long checkoutId,
			boolean okToUpgrade, boolean recover, Object consumer, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {

		String contentType = item.getContentType();
		if (contentType != null && !contentType.equals(DATA_TYPE_ARCHIVE_CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		DatabaseItem dbItem = (DatabaseItem) item;
		ManagedBufferFile bf = null;
		DBHandle dbh = null;
		DataTypeArchiveDB dataTypeArchive = null;
		boolean success = false;
		try {
			bf = dbItem.openForUpdate(checkoutId);
			dbh = new DBHandle(bf, recover, monitor);
			int openMode = okToUpgrade ? DBConstants.UPGRADE : DBConstants.UPDATE;
			dataTypeArchive = new DataTypeArchiveDB(dbh, openMode, monitor, consumer);
			if (checkoutId == FolderItem.DEFAULT_CHECKOUT_ID) {
				getDataTypeArchiveChangeSet(dataTypeArchive, bf);
			}
			if (recover) {
				boolean isRecovered = recoverChangeSet(dataTypeArchive, dbh);
				if (isRecovered) {
					dataTypeArchive.setChanged(true);
				}
			}
			success = true;
			return dataTypeArchive;
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
			t.printStackTrace();
			String msg = t.getMessage();
			if (msg == null) {
				msg = t.toString();
			}
			throw new IOException("Open failed: " + msg);
		}
		finally {
			if (!success) {
				if (dataTypeArchive != null) {
					dataTypeArchive.release(consumer);
				}
				if (dbh != null) {
					dbh.close();
				}
				if (bf != null) {
					bf.dispose();
				}
			}
		}
	}

	private boolean recoverChangeSet(DataTypeArchiveDB dataTypeArchive, DBHandle dbh)
			throws IOException {
		boolean recovered = false;
		DataTypeArchiveDBChangeSet changeSet =
			(DataTypeArchiveDBChangeSet) dataTypeArchive.getChangeSet();
		BufferFile cf = dbh.getRecoveryChangeSetFile();
		if (cf != null) {
			DBHandle cfh = null;
			try {
				cfh = new DBHandle(cf);
				changeSet.read(cfh);
				recovered = true;
			}
			finally {
				if (cfh != null) {
					cfh.close();
				}
				cf.dispose();
			}
		}
		return recovered;
	}

	private DataTypeArchiveDBChangeSet getDataTypeArchiveChangeSet(
			DataTypeArchiveDB dataTypeArchive, ManagedBufferFile bf) throws IOException {
		DataTypeArchiveDBChangeSet changeSet =
			(DataTypeArchiveDBChangeSet) dataTypeArchive.getChangeSet();
		BufferFile cf = bf.getNextChangeDataFile(true);
		DBHandle cfh = null;
		while (cf != null) {
			try {
				cfh = new DBHandle(cf);
				changeSet.read(cfh);
			}
			finally {
				if (cfh != null) {
					cfh.close();
					cfh = null;
				}
				cf.dispose();
			}
			cf = bf.getNextChangeDataFile(false);
		}
		return changeSet;
	}

	@Override
	public ChangeSet getChangeSet(FolderItem item, int fromVer, int toVer)
			throws VersionException, IOException {
		String contentType = item.getContentType();
		if (contentType != null && !contentType.equals(DATA_TYPE_ARCHIVE_CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		DatabaseItem dbItem = (DatabaseItem) item;
		ManagedBufferFile bf = null;
		DBHandle dbh = null;
		DataTypeArchiveDB dataTypeArchive = null;
		try {
			bf = dbItem.open(toVer, fromVer);
			dbh = new DBHandle(bf);
			int openMode = DBConstants.READ_ONLY;
			dataTypeArchive = new DataTypeArchiveDB(dbh, openMode, null, this);
			return getDataTypeArchiveChangeSet(dataTypeArchive, bf);
		}
		catch (VersionException e) {
			throw e;
		}
		catch (IOException e) {
			throw e;
		}
		catch (Throwable t) {
			Msg.error(this, "getChangeSet failed", t);
			String msg = t.getMessage();
			if (msg == null) {
				msg = t.toString();
			}
			throw new IOException("Open failed: " + msg);
		}
		finally {
			if (dataTypeArchive != null) {
				dataTypeArchive.release(this);
			}
			if (dbh != null) {
				dbh.close();
			}
			if (bf != null) {
				bf.dispose();
			}
		}
	}

	@Override
	public Class<DataTypeArchiveDB> getDomainObjectClass() {
		return DATA_TYPE_ARCHIVE_DOMAIN_OBJECT_CLASS;
	}

	@Override
	public String getContentType() {
		return DATA_TYPE_ARCHIVE_CONTENT_TYPE;
	}

	@Override
	public String getContentTypeDisplayString() {
		return "Data Type Archive";
	}

	@Override
	public String getDefaultToolName() {
		return DATA_TYPE_ARCHIVE_CONTENT_DEFAULT_TOOL;
	}

	@Override
	public Icon getIcon() {
		return DATA_TYPE_ARCHIVE_ICON;
	}

	@Override
	public boolean isPrivateContentType() {
		return false;
	}

	@Override
	public DomainObjectMergeManager getMergeManager(DomainObject resultsObj, DomainObject sourceObj,
			DomainObject originalObj, DomainObject latestObj) {
		return DataTypeArchiveMergeManagerFactory.getMergeManager(resultsObj, sourceObj,
			originalObj, latestObj);
	}

	@Override
	public DataTypeArchiveLinkContentHandler getLinkHandler() {
		return linkHandler;
	}

}

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
package ghidra.trace.database;

import java.io.IOException;

import javax.swing.Icon;

import db.DBHandle;
import db.buffers.BufferFile;
import db.buffers.ManagedBufferFile;
import ghidra.framework.data.*;
import ghidra.framework.model.ChangeSet;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.*;
import ghidra.trace.model.Trace;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.database.DBOpenMode;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceContentHandler extends DBContentHandler {
	public static final String TRACE_CONTENT_TYPE = "Trace";

	@Override
	public long createFile(FileSystem fs, FileSystem userfs, String path, String name,
			DomainObject obj, TaskMonitor monitor)
			throws IOException, InvalidNameException, CancelledException {
		if (!(obj instanceof DBTrace)) {
			throw new IOException("Unsupported domain object: " + obj.getClass().getName());
		}
		return createFile((DBTrace) obj, TRACE_CONTENT_TYPE, fs, path, name, monitor);
	}

	@Override
	public DomainObjectAdapter getImmutableObject(FolderItem item, Object consumer, int version,
			int minChangeVersion, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException {
		String contentType = item.getContentType();
		if (contentType != null && !contentType.equals(TRACE_CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		DatabaseItem dbItem = (DatabaseItem) item;
		ManagedBufferFile bf = null;
		DBHandle dbh = null;
		DBTrace trace = null;
		boolean success = false;
		try {
			bf = dbItem.open(version, minChangeVersion);
			dbh = new DBHandle(bf);
			DBOpenMode openMode = DBOpenMode.READ_ONLY;
			trace = new DBTrace(dbh, openMode, monitor, consumer);
			getTraceChangeSet(trace, bf);
			success = true;
			return trace;
		}
		catch (VersionException | IOException | CancelledException e) {
			throw e;
		}
		catch (Throwable t) {
			Msg.error(this, "GetImmutableObject failed", t);
			String msg = t.getMessage();
			if (msg == null) {
				msg = t.toString();
			}
			throw new IOException("Open failed: " + msg);
		}
		finally {
			if (!success) {
				if (trace != null) {
					trace.release(consumer);
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
	public DomainObjectAdapter getReadOnlyObject(FolderItem item, int version, boolean okToUpgrade,
			Object consumer, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		String contentType = item.getContentType();
		if (contentType != null && !contentType.equals(TRACE_CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		DatabaseItem dbItem = (DatabaseItem) item;
		ManagedBufferFile bf = null;
		DBHandle dbh = null;
		DBTrace trace = null;
		boolean success = false;
		try {
			bf = dbItem.open(version);
			dbh = new DBHandle(bf);
			DBOpenMode openMode = okToUpgrade ? DBOpenMode.UPGRADE : DBOpenMode.UPDATE;
			trace = new DBTrace(dbh, openMode, monitor, consumer);
			getTraceChangeSet(trace, bf);
			trace.setTraceUserData(new DBTraceUserData(trace));
			success = true;
			return trace;
		}
		catch (VersionException | IOException | CancelledException e) {
			throw e;
		}
		catch (Throwable t) {
			Msg.error(this, "getReadOnlyObject failed", t);
			t.printStackTrace();
			String msg = t.getMessage();
			if (msg == null) {
				msg = t.toString();
			}
			throw new IOException("Open failed: " + msg);
		}
		finally {
			if (!success) {
				if (trace != null) {
					trace.release(consumer);
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
	public DomainObjectAdapter getDomainObject(FolderItem item, FileSystem userfs, long checkoutId,
			boolean okToUpgrade, boolean recover, Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException {
		String contentType = item.getContentType();
		if (contentType != null && !contentType.equals(TRACE_CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		DatabaseItem dbItem = (DatabaseItem) item;
		ManagedBufferFile bf = null;
		DBHandle dbh = null;
		DBTrace trace = null;
		boolean success = false;
		try {
			bf = dbItem.openForUpdate(checkoutId);
			dbh = new DBHandle(bf, recover, monitor);
			DBOpenMode openMode = okToUpgrade ? DBOpenMode.UPGRADE : DBOpenMode.UPDATE;
			trace = new DBTrace(dbh, openMode, monitor, consumer);
			if (checkoutId == FolderItem.DEFAULT_CHECKOUT_ID) {
				getTraceChangeSet(trace, bf);
			}
			if (recover) {
				recoverChangeSet(trace, dbh);
				trace.setChanged(true);
			}
			trace.setTraceUserData(getTraceUserData(trace, dbItem, userfs, monitor));
			success = true;
			return trace;
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
			throw new IOException("Open failed: " + msg);
		}
		finally {
			if (!success) {
				if (trace != null) {
					trace.release(consumer);
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

	private DBTraceUserData getTraceUserData(DBTrace trace, FolderItem traceItem, FileSystem userfs,
			TaskMonitor monitor) throws CancelledException, IOException, VersionException {
		if (userfs == null) {
			return null;
		}
		DBHandle userDbh =
			openAssociatedUserFile(traceItem.getFileID(), TRACE_CONTENT_TYPE, userfs, monitor);
		if (userDbh != null) {
			return new DBTraceUserData(userDbh, trace, monitor);
		}
		return new DBTraceUserData(trace);
	}

	private void recoverChangeSet(DBTrace trace, DBHandle dbh) throws IOException {
		DBTraceChangeSet changeSet = trace.getChangeSet();
		BufferFile cf = dbh.getRecoveryChangeSetFile();
		if (cf != null) {
			DBHandle cfh = null;
			try {
				cfh = new DBHandle(cf);
				changeSet.read(cfh);
			}
			finally {
				if (cfh != null) {
					cfh.close();
				}
				cf.dispose();
			}
		}
	}

	private DBTraceChangeSet getTraceChangeSet(DBTrace trace, ManagedBufferFile bf)
			throws IOException {
		DBTraceChangeSet changeSet = trace.getChangeSet();
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
		if (contentType != null && !contentType.equals(TRACE_CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		DatabaseItem dbItem = (DatabaseItem) item;
		ManagedBufferFile bf = null;
		DBHandle dbh = null;
		DBTrace trace = null;
		try {
			bf = dbItem.open(toVer, fromVer);
			dbh = new DBHandle(bf);
			DBOpenMode openMode = DBOpenMode.READ_ONLY;
			trace = new DBTrace(dbh, openMode, null, this);
			return getTraceChangeSet(trace, bf);
		}
		catch (VersionException | IOException e) {
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
			if (trace != null) {
				trace.release(this);
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
	public Class<? extends DomainObject> getDomainObjectClass() {
		return DBTrace.class;
	}

	@Override
	public String getContentType() {
		return TRACE_CONTENT_TYPE;
	}

	@Override
	public String getContentTypeDisplayString() {
		return "Trace";
	}

	@Override
	public String getDefaultToolName() {
		return "Debugger"; // TODO: Actually make this tool
	}

	@Override
	public Icon getIcon() {
		return Trace.TRACE_ICON;
	}

	@Override
	public boolean isPrivateContentType() {
		return false;
	}

	@Override
	public DomainObjectMergeManager getMergeManager(DomainObject resultsObj, DomainObject sourceObj,
			DomainObject originalObj, DomainObject latestObj) {
		// TODO:
		return null;
	}
}

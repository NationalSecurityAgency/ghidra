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
import javax.swing.ImageIcon;

import db.*;
import db.buffers.BufferFile;
import db.buffers.ManagedBufferFile;
import ghidra.framework.data.*;
import ghidra.framework.model.ChangeSet;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.*;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * <code>ProgramContentHandler</code> converts between Program instantiations
 * and FolderItem storage.  This class also produces the appropriate Icon for 
 * Program files.
 */
public class ProgramContentHandler extends DBContentHandler {

	// scale just a bit to make a nice, slender document
	public static ImageIcon PROGRAM_ICON = ResourceManager.loadImage("images/program_obj.png");

	public static final String PROGRAM_CONTENT_TYPE = "Program";

	@Override
	public long createFile(FileSystem fs, FileSystem userfs, String path, String name,
			DomainObject obj, TaskMonitor monitor)
			throws IOException, InvalidNameException, CancelledException {

		if (!(obj instanceof ProgramDB)) {
			throw new IOException("Unsupported domain object: " + obj.getClass().getName());
		}
		return createFile((ProgramDB) obj, PROGRAM_CONTENT_TYPE, fs, path, name, monitor);
	}

	@Override
	public DomainObjectAdapter getImmutableObject(FolderItem item, Object consumer, int version,
			int minChangeVersion, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		String contentType = item.getContentType();
		if (contentType != null && !contentType.equals(PROGRAM_CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		DatabaseItem dbItem = (DatabaseItem) item;
		ManagedBufferFile bf = null;
		DBHandle dbh = null;
		ProgramDB program = null;
		boolean success = false;
		try {
			bf = dbItem.open(version, minChangeVersion);
			dbh = new DBHandle(bf);
			int openMode = DBConstants.READ_ONLY;
			program = new ProgramDB(dbh, openMode, monitor, consumer);
			getProgramChangeSet(program, bf);
			success = true;
			return program;
		}
		catch (Field.UnsupportedFieldException e) {
			throw new VersionException(false);
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
				if (program != null) {
					program.release(consumer);
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
		if (contentType != null && !contentType.equals(PROGRAM_CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		DatabaseItem dbItem = (DatabaseItem) item;
		ManagedBufferFile bf = null;
		DBHandle dbh = null;
		ProgramDB program = null;
		boolean success = false;
		try {
			bf = dbItem.open(version);
			dbh = new DBHandle(bf);
			int openMode = okToUpgrade ? DBConstants.UPGRADE : DBConstants.UPDATE;
			program = new ProgramDB(dbh, openMode, monitor, consumer);
			getProgramChangeSet(program, bf);
			program.setProgramUserData(new ProgramUserDataDB(program));
			success = true;
			return program;
		}
		catch (Field.UnsupportedFieldException e) {
			throw new VersionException(false);
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
			t.printStackTrace();
			String msg = t.getMessage();
			if (msg == null) {
				msg = t.toString();
			}
			throw new IOException("Open failed: " + msg);
		}
		finally {
			if (!success) {
				if (program != null) {
					program.release(consumer);
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
			throws IOException, VersionException, CancelledException {

		String contentType = item.getContentType();
		if (contentType != null && !contentType.equals(PROGRAM_CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		DatabaseItem dbItem = (DatabaseItem) item;
		ManagedBufferFile bf = null;
		DBHandle dbh = null;
		ProgramDB program = null;
		boolean success = false;
		try {
			bf = dbItem.openForUpdate(checkoutId);
			dbh = new DBHandle(bf, recover, monitor);
			int openMode = okToUpgrade ? DBConstants.UPGRADE : DBConstants.UPDATE;
			program = new ProgramDB(dbh, openMode, monitor, consumer);
			if (checkoutId == FolderItem.DEFAULT_CHECKOUT_ID) {
				getProgramChangeSet(program, bf);
			}
			if (recover) {
				recoverChangeSet(program, dbh);
				program.setChanged(true);
			}
			program.setProgramUserData(getProgramUserData(program, dbItem, userfs, monitor));
			success = true;
			return program;
		}
		catch (Field.UnsupportedFieldException e) {
			throw new VersionException(false);
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
		finally {
			if (!success) {
				if (program != null) {
					program.release(consumer);
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

	private ProgramUserDataDB getProgramUserData(ProgramDB program, FolderItem programItem,
			FileSystem userfs, TaskMonitor monitor)
			throws CancelledException, IOException, VersionException {
		if (userfs == null) {
			return null;
		}
		DBHandle userDbh =
			openAssociatedUserFile(programItem.getFileID(), PROGRAM_CONTENT_TYPE, userfs, monitor);
		if (userDbh != null) {
			return new ProgramUserDataDB(userDbh, program, monitor);
		}
		return new ProgramUserDataDB(program);
	}

	private void recoverChangeSet(ProgramDB program, DBHandle dbh) throws IOException {
		ProgramDBChangeSet changeSet = (ProgramDBChangeSet) program.getChangeSet();
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

	private ProgramDBChangeSet getProgramChangeSet(ProgramDB program, ManagedBufferFile bf)
			throws IOException {
		ProgramDBChangeSet changeSet = (ProgramDBChangeSet) program.getChangeSet();
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
		if (contentType != null && !contentType.equals(PROGRAM_CONTENT_TYPE)) {
			throw new IOException("Unsupported content type: " + contentType);
		}
		DatabaseItem dbItem = (DatabaseItem) item;
		ManagedBufferFile bf = null;
		DBHandle dbh = null;
		ProgramDB program = null;
		try {
			bf = dbItem.open(toVer, fromVer);
			dbh = new DBHandle(bf);
			int openMode = DBConstants.READ_ONLY;
			program = new ProgramDB(dbh, openMode, null, this);
			return getProgramChangeSet(program, bf);
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
			if (program != null) {
				program.release(this);
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
		return ProgramDB.class;
	}

	@Override
	public String getContentType() {
		return PROGRAM_CONTENT_TYPE;
	}

	@Override
	public String getContentTypeDisplayString() {
		return "Program";
	}

	@Override
	public String getDefaultToolName() {
		return "CodeBrowser";
	}

	@Override
	public Icon getIcon() {
		return PROGRAM_ICON;
	}

	@Override
	public boolean isPrivateContentType() {
		return false;
	}

	@Override
	public DomainObjectMergeManager getMergeManager(DomainObject resultsObj, DomainObject sourceObj,
			DomainObject originalObj, DomainObject latestObj) {
		return ProgramMultiUserMergeManagerFactory.getMergeManager(resultsObj, sourceObj,
			originalObj, latestObj);
	}

}

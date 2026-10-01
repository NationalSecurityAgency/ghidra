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
package ghidra.app.plugin.core.datamgr.archive;

import java.io.IOException;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.services.*;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.database.dtarchive.DataTypeArchiveFactory;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.dtarchive.*;
import ghidra.util.Msg;
import ghidra.util.UniversalID;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Simple, non-ui implementation of the {@link DataTypeArchiveService} interface. This is only
 * used in headless mode (and some tests). The methods of this class are synchronized to protect
 * the openArchives structure and to prevent multiple threads from attempting to open the same
 * archives at the same time. Since this is used in headless mode, they may be multiple threads
 * accessing this service at the same time.
 */
public class BasicDataTypeArchiveService implements DataTypeArchiveService {

	private Map<UniversalID, PersistentDataTypeArchive> openArchives = new HashMap<>();
	protected BuiltInDataTypeManager builtInDataTypesManager;

	public BasicDataTypeArchiveService() {
		this.builtInDataTypesManager = BuiltInDataTypeManager.getDataTypeManager();
	}

	public synchronized void dispose() {
		for (PersistentDataTypeArchive archive : new ArrayList<>(openArchives.values())) {
			closeArchive(archive); // mutates openArchives map
		}
	}

	@Override
	public synchronized DataTypeManager getBuiltInDataTypesManager() {
		return builtInDataTypesManager;
	}

	@Override
	public synchronized DataTypeManager[] getDataTypeManagers() {
		List<DataTypeManager> list = new ArrayList<>();
		list.add(builtInDataTypesManager);
		for (PersistentDataTypeArchive archive : openArchives.values()) {
			list.add(archive.getDataTypeManager());
		}
		return list.toArray(DataTypeManager[]::new);
	}

	@Override
	public synchronized List<PersistentDataTypeArchive> getDataTypeArchives() {
		return new ArrayList<PersistentDataTypeArchive>(openArchives.values());
	}

	@Override
	public synchronized void closeArchive(DataTypeManager dtm) {
		if (dtm instanceof BuiltInDataTypeManager) {
			Msg.info(this, "Cannot close the built-in Data Type Manager");
			return;
		}

		if (dtm instanceof ProgramDataTypeManager) {
			Msg.info(this, "Cannot close the Program's Data Type Manager");
			return;
		}

		PersistentDataTypeArchive archive = openArchives.get(dtm.getUniversalID());
		if (archive == null) {
			Msg.info(this, "Unable close archive; archive not open: '%s'".formatted(dtm.getName()));
			return;
		}
		closeArchive(archive);
	}

	@Override
	public synchronized void closeArchive(PersistentDataTypeArchive archive) {
		openArchives.remove(archive.getDataTypeManager().getUniversalID());
		archive.release(this);
	}

	@Override
	public synchronized FileDataTypeArchive openFileArchive(String archiveName, TaskMonitor monitor)
			throws IOException, DuplicateIdException, CancelledException {
		ResourceFile file = DataTypeArchiveUtility.findArchiveFile(archiveName);
		if (file != null) {
			return openFileArchive(file, false, Upgrade.NO, monitor);
		}
		return null;
	}

	@Override
	public synchronized ProjectDataTypeArchive openProjectArchive(DomainFile domainFile,
			Upgrade upgradeStrategy, Recover recoverStrategy, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException, DuplicateIdException {

		if (!ProjectDataTypeArchive.class.isAssignableFrom(domainFile.getDomainObjectClass())) {
			throw new IOException("Unable to open domain file: '%s', not a data type archive"
					.formatted(domainFile.getName()));
		}

		ProjectDataTypeArchive archive = getOpenArchive(domainFile);
		if (archive == null) {
			boolean okToUpgrade = upgradeStrategy == Upgrade.YES;
			boolean okToRecover = recoverStrategy == Recover.YES;
			archive = openDomainFile(domainFile, okToUpgrade, okToRecover, monitor);
			addArchive(archive);
		}

		return archive;
	}

	private ProjectDataTypeArchive openDomainFile(DomainFile domainFile, boolean okToUpgrade,
			boolean okToRecover, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		ProjectDataTypeArchive dta =
			(ProjectDataTypeArchive) domainFile.getDomainObject(this, false, false, monitor);
		return dta;
	}

	@Override
	public synchronized FileDataTypeArchive openFileArchive(ResourceFile file,
			boolean openForUpdate, Upgrade upgradeStrategy, TaskMonitor monitor)
			throws IOException, DuplicateIdException, CancelledException {
		file = file.getCanonicalFile();
		FileDataTypeArchive archive = getOpenArchive(file);
		if (archive == null) {
			boolean okToUpgrade = upgradeStrategy == Upgrade.YES;
			archive = doOpenFileArchive(file, openForUpdate, okToUpgrade, monitor);
			addArchive(archive);
		}
		return archive;
	}

	private FileDataTypeArchive doOpenFileArchive(ResourceFile file, boolean openForUpdate,
			boolean okToUpgrade, TaskMonitor monitor) throws IOException, CancelledException {
		try {
			if (!openForUpdate) {
				return DataTypeArchiveFactory.openReadOnly(file, this, monitor);
			}
			return DataTypeArchiveFactory.openForUpdate(file, okToUpgrade, this, monitor);
		}
		catch (VersionException e) {
			throw new IOException(e);
		}
	}

	private void addArchive(PersistentDataTypeArchive archive)
			throws DuplicateIdException {
		UniversalID id = archive.getDataTypeManager().getUniversalID();
		PersistentDataTypeArchive existing = openArchives.get(id);
		if (existing != null) {
			if (existing.isClosed()) {
				openArchives.remove(id);
			}
			else {
				archive.release(this);
				throw new DuplicateIdException(archive.getName(), existing.getName());
			}
		}
		openArchives.put(id, archive);
	}

	private FileDataTypeArchive getOpenArchive(ResourceFile file) {
		for (PersistentDataTypeArchive archive : openArchives.values()) {
			if (archive instanceof FileDataTypeArchive fileArchive) {
				if (fileArchive.getFile().equals(file)) {
					if (fileArchive.isClosed()) {
						openArchives.remove(fileArchive.getDataTypeManager().getUniversalID());
						return null;
					}
					return fileArchive;
				}
			}
		}
		return null;
	}

	private ProjectDataTypeArchive getOpenArchive(DomainFile projectFile) {
		for (PersistentDataTypeArchive archive : openArchives.values()) {
			if (archive instanceof ProjectDataTypeArchive projectArchive) {
				if (archive.getDomainFile().equals(projectFile)) {
					if (archive.isClosed()) {
						openArchives.remove(archive.getDataTypeManager().getUniversalID());
						return null;
					}
					return projectArchive;
				}
			}
		}
		return null;
	}
}

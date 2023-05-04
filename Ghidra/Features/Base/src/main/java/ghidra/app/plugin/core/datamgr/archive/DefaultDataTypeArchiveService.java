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

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.services.DataTypeArchiveService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.util.Msg;
import ghidra.util.UniversalID;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Simple, non-ui implementation of the {@link DataTypeArchiveService} interface.
 */
public class DefaultDataTypeArchiveService implements DataTypeArchiveService {
	protected record DataTypeManagerInfo(ResourceFile file, DomainObject domainObject, String name,
			DataTypeManager dtm) {
		public boolean isClosed() {
			return dtm instanceof FileDataTypeManager fdtm
					? fdtm.isClosed()
					: false;
		}
	}

	protected Map<UniversalID, DataTypeManagerInfo> openDTMs = new HashMap<>();
	protected BuiltInDataTypeManager builtInDataTypesManager;

	public DefaultDataTypeArchiveService() {
		this.builtInDataTypesManager = BuiltInDataTypeManager.getDataTypeManager();
	}

	public synchronized void dispose() {
		for (DataTypeManagerInfo dtmInfo : new ArrayList<>(openDTMs.values())) {
			closeDTM(dtmInfo); // mutates openDTMs map
		}
	}

	@Override
	public DataTypeManager getBuiltInDataTypesManager() {
		return builtInDataTypesManager;
	}

	@Override
	public DataTypeManager[] getDataTypeManagers() {
		List<DataTypeManager> dtmList = openDTMs.values()
				.stream()
				.filter(dtmInfo -> !dtmInfo.isClosed())
				.map(dtmInfo -> dtmInfo.dtm())
				.collect(Collectors.toList());
		return dtmList.toArray(DataTypeManager[]::new);
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

		DataTypeManagerInfo dtmInfo = openDTMs.get(dtm.getUniversalID());
		if (dtmInfo == null) {
			Msg.info(this, "Unable close archive; archive not open: '%s'".formatted(dtm.getName()));
			return;
		}

		beforeCloseDataTypeManager(dtmInfo);
		openDTMs.remove(dtm.getUniversalID());

		if (dtmInfo.domainObject != null) {
			dtmInfo.domainObject.release(this);
		}
		dtmInfo.dtm.close();

		afterCloseDataTypeManager(dtmInfo);
	}

	@Override
	public Archive openArchive(DataTypeArchive dataTypeArchive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Archive openArchive(File file, boolean acquireWriteLock)
			throws IOException, DuplicateIdException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeManager openDataTypeArchive(String archiveName)
			throws IOException, DuplicateIdException {
		ResourceFile file = DataTypeArchiveUtility.findArchiveFile(archiveName);
		if (file != null) {
			return openArchive(file, false);
		}
		return null;
	}

	@Override
	public synchronized DataTypeManager openArchive(DomainFile domainFile, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException, DuplicateIdException {

		if (!DataTypeArchive.class.isAssignableFrom(domainFile.getDomainObjectClass())) {
			throw new IOException("Unable to open domain file: '%s', not a data type archive"
					.formatted(domainFile.getName()));
		}

		DataTypeManagerInfo dtmInfo = getOpenDTMInfo(domainFile);
		if (dtmInfo == null) {
			DataTypeArchive dta = openDomainFile(domainFile, monitor);
			DataTypeManager dtm = dta.getDataTypeManager();
			dtmInfo = addDTM(new DataTypeManagerInfo(null, dta, domainFile.getPathname(), dtm));
		}

		return dtmInfo.dtm;
	}

	protected DataTypeArchive openDomainFile(DomainFile domainFile, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		DataTypeArchive dta =
			(DataTypeArchive) domainFile.getDomainObject(this, false, false, monitor);
		return dta;
	}

	@Override
	public synchronized DataTypeManager openArchive(ResourceFile file, boolean acquireWriteLock)
			throws IOException, DuplicateIdException {

		file = file.getCanonicalFile();
		DataTypeManagerInfo dtmInfo = getOpenDTMInfo(file);
		if (dtmInfo == null) {
			FileDataTypeManager fileDTM =
				FileDataTypeManager.openFileArchive(file, acquireWriteLock);

			dtmInfo = addDTM(new DataTypeManagerInfo(file, null, file.getName(), fileDTM));
		}
		return dtmInfo.dtm;
	}

	protected DataTypeManagerInfo addDTM(DataTypeManagerInfo dtmInfo) throws DuplicateIdException {
		DataTypeManagerInfo existingDTM = openDTMs.get(dtmInfo.dtm.getUniversalID());
		if (existingDTM != null) {
			if (existingDTM.isClosed()) {
				openDTMs.remove(dtmInfo.dtm.getUniversalID());
			}
			else {
				dtmInfo.dtm.close();
				throw new DuplicateIdException(dtmInfo.name(), existingDTM.name());
			}
		}
		openDTMs.put(dtmInfo.dtm.getUniversalID(), dtmInfo);
		afterAddDataTypeManager(dtmInfo);
		return dtmInfo;
	}

	protected void closeDTM(DataTypeManagerInfo dtmInfo) {
		beforeCloseDataTypeManager(dtmInfo);
		openDTMs.remove(dtmInfo.dtm.getUniversalID());

		if (dtmInfo.domainObject != null) {
			dtmInfo.domainObject.release(this);
		}
		dtmInfo.dtm.close();

		afterCloseDataTypeManager(dtmInfo);
	}

	private DataTypeManagerInfo getOpenDTMInfo(ResourceFile file) {
		for (DataTypeManagerInfo dtmInfo : openDTMs.values()) {
			if (dtmInfo.file != null && dtmInfo.file.equals(file)) {
				if (dtmInfo.isClosed()) {
					openDTMs.remove(dtmInfo.dtm.getUniversalID());
					return null;
				}
				return dtmInfo;
			}
		}
		return null;
	}

	private DataTypeManagerInfo getOpenDTMInfo(DomainFile projectFile) {
		for (DataTypeManagerInfo dtmInfo : openDTMs.values()) {
			if (dtmInfo.domainObject != null &&
				dtmInfo.domainObject.getDomainFile().equals(projectFile)) {
				if (dtmInfo.isClosed()) {
					openDTMs.remove(dtmInfo.dtm.getUniversalID());
					return null;
				}
				return dtmInfo;
			}
		}
		return null;
	}

	protected void afterAddDataTypeManager(DataTypeManagerInfo dtmInfo) {
		// override as needed
	}

	protected void afterCloseDataTypeManager(DataTypeManagerInfo dtmInfo) {
		// override as needed
	}

	protected void beforeCloseDataTypeManager(DataTypeManagerInfo dtmInfo) {
		// override as needed
	}

}

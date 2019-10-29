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
package ghidra.app.plugin.core.analysis;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import javax.swing.tree.TreePath;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.plugin.core.datamgr.util.DataTypeComparator;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.util.HelpLocation;
import ghidra.util.UniversalID;

// FIXME!! TESTING
public class DefaultDataTypeManagerService implements DataTypeManagerService {

	private Map<String, FileDataTypeManager> archiveMap = new HashMap<>();
	private DataTypeManager builtInDataTypesManager = BuiltInDataTypeManager.getDataTypeManager();

	void dispose() {
		for (FileDataTypeManager dtfm : archiveMap.values()) {
			dtfm.close();
		}
		archiveMap.clear();
	}

	// TODO: This implementation needs to be consolidated with the tool-based service in 
	// favor of a single static data type manager service used by both the tool and 
	// headless scenarios

	private FileDataTypeManager findOpenFileArchiveWithID(UniversalID universalID) {
		if (universalID == null) {
			return null;
		}
		for (FileDataTypeManager dtm : archiveMap.values()) {
			if (universalID.equals(dtm.getUniversalID()) && !dtm.isClosed()) {
				return dtm;
			}
		}
		return null;
	}

	@Override
	public synchronized DataTypeManager openDataTypeArchive(String archiveName)
			throws IOException, DuplicateIdException {

		if (archiveMap.containsKey(archiveName)) {
			FileDataTypeManager dtm = archiveMap.get(archiveName);
			if (!dtm.isClosed()) {
				return dtm;
			}
			archiveMap.remove(archiveName);
		}

		ResourceFile archiveFile = DataTypeArchiveUtility.findArchiveFile(archiveName);
		if (archiveFile == null) {
			return null;
		}

		FileDataTypeManager fileDtm = FileDataTypeManager.openFileArchive(archiveFile, false);

		FileDataTypeManager existingDtm = findOpenFileArchiveWithID(fileDtm.getUniversalID());
		if (existingDtm != null) {
			fileDtm.close();
			throw new DuplicateIdException(fileDtm.getName(), existingDtm.getName());
		}

		archiveMap.put(archiveName, fileDtm);

		return fileDtm;
	}

	@Override
	public void closeArchive(DataTypeManager dtm) {

		String archiveName = null;
		Set<Entry<String, FileDataTypeManager>> entries = archiveMap.entrySet();
		for (Entry<String, FileDataTypeManager> entry : entries) {
			FileDataTypeManager manager = entry.getValue();
			if (manager.equals(dtm)) {
				archiveName = entry.getKey();
				break;
			}

		}

		if (archiveName != null) {
			FileDataTypeManager manager = archiveMap.get(archiveName);
			archiveMap.remove(archiveName);
			manager.close();
		}
	}

	@Override
	public DataTypeManager[] getDataTypeManagers() {
		ArrayList<FileDataTypeManager> dtmList = new ArrayList<>();
		for (FileDataTypeManager dtm : archiveMap.values()) {
			if (!dtm.isClosed()) {
				dtmList.add(dtm);
			}
		}
		DataTypeManager[] managers = new DataTypeManager[dtmList.size()];
		dtmList.toArray(managers);
		return managers;
	}

	@Override
	public HelpLocation getEditorHelpLocation(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isEditable(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void edit(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeManager getBuiltInDataTypesManager() {
		return builtInDataTypesManager;
	}

	@Override
	public DataType getDataType(String filterText) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getDataType(TreePath selectedTreeNode) {
		if (selectedTreeNode == null) {
			return null;
		}
		throw new UnsupportedOperationException();
	}

	@Override
	public List<DataType> getFavorites() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getRecentlyUsed() {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<DataType> getSortedDataTypeList() {
		List<DataType> dataTypes =
			builtInDataTypesManager.getDataTypes(BuiltInSourceArchive.INSTANCE);
		dataTypes.sort(new DataTypeComparator());
		return dataTypes;
//		throw new UnsupportedOperationException();
	}

	@Override
	public void removeDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setDataTypeSelected(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setRecentlyUsed(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Set<String> getPossibleEquateNames(long value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Archive openArchive(File file, boolean acquireWriteLock) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Archive openArchive(DataTypeArchive dataTypeArchive) {
		throw new UnsupportedOperationException();
	}
}

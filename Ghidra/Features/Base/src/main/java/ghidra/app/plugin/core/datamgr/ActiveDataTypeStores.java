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
package ghidra.app.plugin.core.datamgr;

import java.util.*;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.archive.InvalidArchive;
import ghidra.framework.data.DomainFileProxy;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.*;
import ghidra.program.model.listing.Program;
import ghidra.util.*;

/**
 * Class to track and manage all the open DataTypeStores ( BuiltInDataTypeManager, the active
 * program, FileDataTypeArchives, and Project DataTypeArchives). This class adds
 * DataTypeManagerListers to each corresponding DataTypeManager and consolidates those events into
 * ArchiveManagerListener events that are used by GUI elements such as the DataTypes tree to keep
 * it in synch with the state of the archives.
 */
class ActiveDataTypeStores {

	private Program program;
	private DataTypeManager builtInDataTypesManager;
	private List<PersistentDataTypeArchive> openArchives = new ArrayList<>();
	private Map<UniversalID, InvalidArchive> invalidArchives = new HashMap<>();

	private DataTypeIndexer dataTypeIndexer;
	private DataTypeManagerListenerDelegate listenerDelegate;
	private List<DataTypeManagerChangeListener> dataTypeManagerListeners = new ArrayList<>();
	private List<ArchiveManagerListener> archiveManagerlisteners = new ArrayList<>();

	// maintain a set of archives that should automatically be opened the next time the tool is run
	private Set<PersistentDataTypeArchive> rememberedArchives = new HashSet<>();

	// Updated anytime any datatype or category changes in any open archive, including the program
	// archive. Currently used by data type tree nodes to know if their tooltip cache is stale.
	private volatile long modCount = 0;

	ActiveDataTypeStores() {
		listenerDelegate = new DataTypeManagerListenerDelegate();
		builtInDataTypesManager = BuiltInDataTypeManager.getDataTypeManager();
		builtInDataTypesManager.addDataTypeManagerListener(listenerDelegate);
		dataTypeIndexer = new DataTypeIndexer();
		dataTypeIndexer.addDataTypeManager(builtInDataTypesManager);
	}

	void dispose() {
		removeAllArchives();
		dataTypeIndexer.removeDataTypeManager(builtInDataTypesManager);
		builtInDataTypesManager.removeDataTypeManagerListener(listenerDelegate);

	}

	void setProgram(Program newProgram) {
		if (this.program != null) {
			this.program.getDataTypeManager().removeDataTypeManagerListener(listenerDelegate);
			dataTypeIndexer.removeDataTypeManager(this.program.getDataTypeManager());
			notifyProgramClosed();
			this.program = null;
		}
		if (newProgram != null) {
			this.program = newProgram;
			newProgram.getDataTypeManager().addDataTypeManagerListener(listenerDelegate);
			dataTypeIndexer.addDataTypeManager(newProgram.getDataTypeManager());
			notifyProgramOpened();
		}
	}

	void addArchive(PersistentDataTypeArchive archive, boolean rememberInTool) {
		archive.addConsumer(this);
		openArchives.add(archive);
		syncArchiveNames(archive);
		archive.getDataTypeManager().addDataTypeManagerListener(listenerDelegate);
		dataTypeIndexer.addDataTypeManager(archive.getDataTypeManager());
		if (rememberInTool) {
			rememberedArchives.add(archive);
		}
		notifyArchiveOpened(archive);
	}

	/**
	 * Removes all open archives from the service
	 */
	void removeAllArchives() {
		// this list will get modified as we close archives, so work from a copy
		List<PersistentDataTypeArchive> copy = new ArrayList<>(openArchives);
		for (PersistentDataTypeArchive archive : copy) {
			removeArchive(archive);
		}
	}

	/**
	 * Closes the given archive.
	 * @param archive the archive to close in the tool
	 */
	void removeArchive(PersistentDataTypeArchive archive) {

		if (!openArchives.remove(archive)) {
			return;
		}

		archive.getDataTypeManager().removeDataTypeManagerListener(listenerDelegate);
		dataTypeIndexer.removeDataTypeManager(archive.getDataTypeManager());

		rememberedArchives.remove(archive);
		archive.release(this);
		notifyArchiveClosed(archive);
	}

	/**
	 * Adds an ArchiveManagerListener
	 * @param listener the listener
	 */
	void addArchiveManagerListener(ArchiveManagerListener listener) {
		archiveManagerlisteners.add(listener);
	}

	boolean contains(FileDataTypeArchive archive) {
		return openArchives.contains(archive);
	}

	boolean isRemembered(PersistentDataTypeArchive archive) {
		return rememberedArchives.contains(archive);
	}

	ProjectDataTypeArchive getArchiveForDomainFile(DomainFile domainFile, int version) {
		for (PersistentDataTypeArchive archive : openArchives) {
			if (archive instanceof ProjectDataTypeArchive projectArchive) {
				DomainFile openedDf = projectArchive.getDomainFile();
				int openedVersion = openedDf.getVersion();
				if (openedDf instanceof DomainFileProxy proxy) {
					openedDf = proxy.getOriginalDomainFile();
				}
				if (openedVersion == version && domainFile.equals(openedDf)) {
					return projectArchive;
				}
			}
		}
		return null;
	}

	FileDataTypeArchive getArchiveForFile(ResourceFile file) {
		for (PersistentDataTypeArchive archive : openArchives) {
			if (archive instanceof FileDataTypeArchive fileArchive) {
				if (file.equals(fileArchive.getFile())) {
					return fileArchive;
				}
			}
		}
		return null;
	}

	void archiveNameChanged(String fileId, String newName) {
		if (program != null) {
			updateSourceArchiveName(program.getDataTypeManager(), fileId, newName);
		}
		for (PersistentDataTypeArchive archive : openArchives) {
			if (!archive.isChangeable()) {
				continue;
			}
			DataTypeManager dataTypeManager = archive.getDataTypeManager();
			updateSourceArchiveName(dataTypeManager, fileId, newName);
		}
	}

	/**
	 * Removes an ArchiveManagerListene3r
	 * @param listener the listener to remove
	 */
	void removeArchiveManagerListener(ArchiveManagerListener listener) {
		archiveManagerlisteners.remove(listener);
	}

	/**
	 * {@return a list of all open DataTypeManagers in the tool}
	 */
	DataTypeManager[] getDataTypeManagers() {
		List<DataTypeManager> managers = new ArrayList<>();
		managers.add(builtInDataTypesManager);
		if (program != null) {
			managers.add(program.getDataTypeManager());
		}
		for (PersistentDataTypeArchive archive : openArchives) {
			managers.add(archive.getDataTypeManager());
		}
		return managers.toArray(new DataTypeManager[managers.size()]);
	}

	/**
	 * {@return a list of all open file or project archives}
	 */
	List<PersistentDataTypeArchive> getArchives() {
		return new ArrayList<>(openArchives);
	}

	/**
	 * Returns all favorite DataTypes in all archives.
	 * @return all favorite DataTypes in all archives.
	 */
	List<DataType> getFavoriteDataTypes() {
		List<DataType> list = new ArrayList<>();
		list.addAll(builtInDataTypesManager.getFavorites());
		if (program != null) {
			list.addAll(program.getDataTypeManager().getFavorites());
		}
		for (PersistentDataTypeArchive archive : openArchives) {
			DataTypeManager dataTypeManager = archive.getDataTypeManager();
			list.addAll(dataTypeManager.getFavorites());
		}

		return list;
	}

	Set<PersistentDataTypeArchive> getRememberedArchives() {
		return rememberedArchives;
	}

	/**
	 * {@return a list of all open file archives in the tool}
	 */
	List<FileDataTypeArchive> getOpenFileArchives() {
		List<FileDataTypeArchive> archiveList = new ArrayList<>();
		for (PersistentDataTypeArchive archive : openArchives) {
			if (archive instanceof FileDataTypeArchive fileArchive) {
				archiveList.add(fileArchive);
			}
		}
		return archiveList;
	}

	/**
	 * {@return a list of all open project archives in the tool}
	 */
	List<ProjectDataTypeArchive> getOpenProjectArchives() {
		List<ProjectDataTypeArchive> archiveList = new ArrayList<>();
		for (PersistentDataTypeArchive archive : openArchives) {
			if (archive instanceof ProjectDataTypeArchive projectArchive) {
				archiveList.add(projectArchive);
			}
		}
		return archiveList;
	}

	List<DataType> getSortedDataTypeList() {
		return dataTypeIndexer.getSortedDataTypeList();
	}

	List<CategoryPath> getSortedCategoryPathList() {
		return dataTypeIndexer.getSortedCategoryPathList();
	}

	/**
	 * Adds a listener for when DataTypes are added/removed/changed.
	 * @param listener the listener to be notified
	 */
	void addDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		dataTypeManagerListeners.add(listener);
	}

	void removeDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		dataTypeManagerListeners.remove(listener);
	}

	/**
	 * {@return the DatatypeManager associated with the given SourceArchive}
	 * @param source the SourceArchive to find its associated DataTypeManager
	 */
	DataTypeManager getDataTypeManager(SourceArchive source) {
		return getDataTypeManager(source.getSourceArchiveID());
	}

	DataTypeManager getDataTypeManager(UniversalID id) {
		for (PersistentDataTypeArchive archive : openArchives) {
			DataTypeManager dataTypeManager = archive.getDataTypeManager();
			UniversalID universalID = dataTypeManager.getUniversalID();
			if ((universalID != null) && universalID.equals(id)) {
				return dataTypeManager;
			}
		}
		return null;
	}

	/**
	 * Returns the current modification count which is incremented anytime any archive or any
	 * category or datatype it contains is changed in any way. This includes the datatypes in
	 * the current program.
	 * @return the current modification count.
	 */
	long getModificationCount() {
		return modCount;
	}

	boolean isAlreadyOpen(SourceArchive source) {
		if (getDataTypeManager(source) != null) {
			return true;
		}
		return invalidArchives.containsKey(source.getSourceArchiveID());
	}

	void createInvalidArchive(SourceArchive sourceArchive) {
		String name = sourceArchive.getName();
		UniversalID id = sourceArchive.getSourceArchiveID();
		ArchiveType type = sourceArchive.getArchiveType();
		String domainFileId = sourceArchive.getDomainFileID();

		InvalidArchive invalidArchive = new InvalidArchive(name, id, type, domainFileId);
		invalidArchives.put(id, invalidArchive);
		notifyInvalidArchiveAdded(invalidArchive);

	}

	/**
	 * Removes the given InvalidArchive from the tool
	 * @param archive the invalid archive to remove from the tool
	 */
	void removeInvalidArchive(InvalidArchive archive) {
		invalidArchives.remove(archive.id());
		notifyInvalidArchiveRemoved(archive);
	}

	Program getProgram() {
		return program;
	}

	List<InvalidArchive> getInvalidArchives() {
		return new ArrayList<>(invalidArchives.values());
	}

	void notifyStateChanged(DataTypeStore dataTypeStore) {
		Swing.runNow(() -> {
			for (ArchiveManagerListener listener : archiveManagerlisteners) {
				listener.stateChanged(dataTypeStore);
			}
		});
	}

	private void notifyProgramClosed() {
		SystemUtilities.runSwingNow(() -> {
			for (ArchiveManagerListener listener : archiveManagerlisteners) {
				listener.programClosed(program);
			}
		});
	}

	private void notifyArchiveOpened(PersistentDataTypeArchive archive) {
		SystemUtilities.runSwingNow(() -> {
			for (ArchiveManagerListener listener : archiveManagerlisteners) {
				listener.archiveOpened(archive);
			}
		});
	}

	private void notifyInvalidArchiveAdded(InvalidArchive archive) {
		SystemUtilities.runSwingNow(() -> {
			for (ArchiveManagerListener listener : archiveManagerlisteners) {
				listener.invalidArchiveAdded(archive);
			}
		});
	}

	private void notifyInvalidArchiveRemoved(InvalidArchive archive) {
		SystemUtilities.runSwingNow(() -> {
			for (ArchiveManagerListener listener : archiveManagerlisteners) {
				listener.invalidArchiveRemoved(archive);
			}
		});
	}

	private void notifyArchiveClosed(PersistentDataTypeArchive archive) {
		SystemUtilities.runSwingNow(() -> {
			for (ArchiveManagerListener listener : archiveManagerlisteners) {
				listener.archiveClosed(archive);
			}
		});
	}

	private void notifyProgramOpened() {
		SystemUtilities.runSwingNow(() -> {
			for (ArchiveManagerListener listener : archiveManagerlisteners) {
				listener.programOpened(program);
			}
		});
	}

	/**
	 * Update the given archive and any other open archives to have the up-to-date archive names, 
	 * as names may have changed while archives were not open.
	 * @param archive the archive
	 */
	private void syncArchiveNames(PersistentDataTypeArchive archive) {
		try {
			DataTypeManager dtm = archive.getDataTypeManager();
			if (program != null) {
				synchronizeSourceArchiveNames(dtm, program.getDataTypeManager());
			}
			for (PersistentDataTypeArchive openArchive : openArchives) {
				synchronizeSourceArchiveNames(dtm, openArchive.getDataTypeManager());
			}
		}
		catch (Exception e) {
			// can't update now (we are probably immutable), no problem
		}
	}

	private void synchronizeSourceArchiveNames(DataTypeManager dtm1, DataTypeManager dtm2) {
		updateSourceArchiveName(dtm1, dtm2);
		updateSourceArchiveName(dtm2, dtm1);
	}

	private void updateSourceArchiveName(DataTypeManager destination, DataTypeManager source) {
		if (!destination.getDataStore().isChangeable()) {
			return;
		}
		destination.withTransaction("Udaate Data Tpye Source Archive Name", () -> {
			UniversalID id = source.getUniversalID();
			String name = source.getName();
			destination.updateSourceArchiveName(id, name);
		});

	}

	private void updateSourceArchiveName(DataTypeManager dataTypeManager, String fileID,
			String name) {
		dataTypeManager.withTransaction("Update Data Type Source Archive Name",
			() -> dataTypeManager.updateSourceArchiveName(fileID, name));
	}

	class DataTypeManagerListenerDelegate implements DataTypeManagerChangeListener {

		@Override
		public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.categoryAdded(dtm, path);
			}
		}

		@Override
		public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.categoryMoved(dtm, oldPath, newPath);
			}
		}

		@Override
		public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.categoryRemoved(dtm, path);
			}
		}

		@Override
		public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath,
				CategoryPath newPath) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.categoryRenamed(dtm, oldPath, newPath);
			}
		}

		@Override
		public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.dataTypeAdded(dtm, path);
			}
		}

		@Override
		public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.dataTypeChanged(dtm, path);
			}
		}

		@Override
		public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.dataTypeMoved(dtm, oldPath, newPath);
			}
		}

		@Override
		public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.dataTypeRemoved(dtm, path);
			}
		}

		@Override
		public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.dataTypeRenamed(dtm, oldPath, newPath);
			}
		}

		@Override
		public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath, DataType newDataType) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.dataTypeReplaced(dtm, oldPath, newPath, newDataType);
			}
		}

		@Override
		public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.favoritesChanged(dtm, path, isFavorite);
			}
		}

		@Override
		public void sourceArchiveAdded(DataTypeManager dataTypeManager,
				SourceArchive dataTypeSource) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.sourceArchiveAdded(dataTypeManager, dataTypeSource);
			}
		}

		@Override
		public void sourceArchiveChanged(DataTypeManager dataTypeManager,
				SourceArchive dataTypeSource) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.sourceArchiveChanged(dataTypeManager, dataTypeSource);
			}
		}

		@Override
		public void programArchitectureChanged(DataTypeManager dataTypeManager) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.programArchitectureChanged(dataTypeManager);
			}
		}

		@Override
		public void restored(DataTypeManager dataTypeManager) {
			modCount++;
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.restored(dataTypeManager);
			}
		}
	}

}

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

import java.awt.Component;
import java.awt.event.ActionListener;
import java.io.*;
import java.rmi.ConnectException;
import java.util.*;

import docking.widgets.OptionDialog;
import docking.widgets.pathmanager.PathManager;
import generic.jar.ResourceFile;
import generic.util.Path;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.editor.DataTypeEditorManager;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.util.HelpTopics;
import ghidra.framework.client.*;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.FileSystem;
import ghidra.program.database.DataTypeArchiveContentHandler;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.*;

/**
 * Helper class to manage the archive files.
 */

public class DataTypeManagerHandler {

	private static final String CONTENT_NAME = "Data Type Archive";
	private final static String ARCHIVE_NAMES = "ArchiveNames";
	private static final String RELATIVE_PATH_PREFIX = ".";
	private static final String PROJECT_NAME_DELIMETER = ":";
	private final static String RECENT_NAMES = "RecentArchiveNames";
	private static final String FAVORITES = "Favorite Dts";

	private static final String[] UNALLOWED_ARCHIVE_PATH_FRAGMENTS = new String[] {
		"/Ghidra/Extensions/", "/Ghidra/docs/", "/Ghidra/Features/", "/Ghidra/Test/" };

	public static final String OLD_DATA_TYPE_ARCHIVE_PATH_KEY = "DATA_TYPE_ARCHIVE_PATH";
	public static final String DATA_TYPE_ARCHIVE_PATH_KEY = "DATATYPE_ARCHIVE_PATHS";
	public static final String DISABLED_DATA_TYPE_ARCHIVE_PATH_KEY =
		"DISABLED_DATA_TYPE_ARCHIVE_PATH";

	private ProgramArchive programArchive;
	private List<Archive> openArchives = new ArrayList<>();
	private Set<String> initiallyOpenedFileArchiveNames = new HashSet<>();
	private Set<String> userOpenedFileArchiveNames = new HashSet<>();
	private Set<String> knownOpenFileArchiveNames = new HashSet<>();
	private Map<UniversalID, InvalidFileArchive> invalidArchives = new HashMap<>();

	private DataTreeDialog dataTreeSaveDialog;
	private CreateDataTypeArchiveDataTreeDialog dataTreeCreateDialog;
	private boolean treeDialogCancelled = false;
	private DomainFileFilter domainFileFilter;

	private DataTypeIndexer dataTypeIndexer;
	private List<ArchiveManagerListener> archiveManagerlisteners = new ArrayList<>();
	private List<DataTypeManagerChangeListener> dataTypeManagerListeners = new ArrayList<>();

	private RecentlyUsedDataType recentlyUsedDataType = new RecentlyUsedDataType();

	private BuiltInDataTypeManager builtInDataTypesManager;
	private final DataTypeManagerPlugin plugin;
	private PluginTool tool;
	private DataTypeManagerListenerDelegate listenerDelegate;
	private MyFolderListener folderListener;

	public DataTypeManagerHandler(DataTypeManagerPlugin plugin) {
		this.plugin = plugin;
		this.tool = plugin.getTool();
		listenerDelegate = new DataTypeManagerListenerDelegate();
		builtInDataTypesManager = BuiltInDataTypeManager.getDataTypeManager();
		builtInDataTypesManager.addDataTypeManagerListener(listenerDelegate);
		initializeFavorites();

		dataTypeIndexer = new DataTypeIndexer();
		dataTypeIndexer.addDataTypeManager(builtInDataTypesManager);
		openArchives.add(new BuiltInArchive(this, builtInDataTypesManager));

		domainFileFilter = f -> {
			Class<?> c = f.getDomainObjectClass();
			return DataTypeArchive.class.isAssignableFrom(c);
		};

		folderListener = new MyFolderListener();
		tool.getProject().getProjectData().addDomainFolderChangeListener(folderListener);
	}

	public void dispose() {
		dataTypeIndexer.removeDataTypeManager(builtInDataTypesManager);
		builtInDataTypesManager.removeDataTypeManagerListener(listenerDelegate);
		tool.getProject().getProjectData().removeDomainFolderChangeListener(folderListener);
	}

	/**
	 * Notification that the given program is open. Add the root category
	 * for the program to any provider that is open.
	 */
	public void programOpened(Program program) {
		programArchive = new ProgramArchive(program);
		openProgramArchives(program);
		addArchive(programArchive);
	}

	/**
	 * Notification that the program is closed. Remove the root category
	 * for the program from the provider.
	 */
	public void programClosed() {

		programArchive.getDataTypeManager().removeDataTypeManagerListener(listenerDelegate);
		dataTypeIndexer.removeDataTypeManager(programArchive.getDataTypeManager());
		openArchives.remove(programArchive);
		fireArchiveClosed(programArchive);
		programArchive = null;
	}

	private void openProgramArchives(Program program) {
		DataTypeManager programDataTypeManager = program.getDataTypeManager();
		List<SourceArchive> sources = programDataTypeManager.getSourceArchives();
		for (SourceArchive dataTypeSource : sources) {
			if (isOpen(dataTypeSource) || isKnownInvalidArchive(dataTypeSource)) {
				continue;
			}
			switch (dataTypeSource.getArchiveType()) {
				case PROJECT:
					openProjectArchive(dataTypeSource);
					break;
				case FILE:
					openFileArchive(dataTypeSource);
					break;
				default:
					// all other cases do nothing
					break;
			}

		}
	}

	private boolean isOpen(SourceArchive dataTypeSource) {
		List<Archive> allArchives = getAllArchives();
		for (Archive archive : allArchives) {
			DataTypeManager dataTypeManager = archive.getDataTypeManager();
			UniversalID universalID = dataTypeManager.getUniversalID();
			if ((universalID != null) && universalID.equals(dataTypeSource.getSourceArchiveID())) {
				return true;
			}
		}
		return false;
	}

	private void openProjectArchive(SourceArchive dataTypeSource) {
		String domainFileID = dataTypeSource.getDomainFileID();
		DomainFile domainFile =
			plugin.getTool().getProject().getProjectData().getFileByID(domainFileID);
		if (domainFile == null) {
			createInvalidArchiveNode(dataTypeSource);
			return;
		}
		plugin.openArchive(domainFile);
	}

	private void updateSourceArchiveName(DataTypeManager dataTypeManager, String fileID,
			String name) {
		int transactionID =
			dataTypeManager.startTransaction("Update Data Type Source Archive Name");
		try {
			dataTypeManager.updateSourceArchiveName(fileID, name);
		}
		finally {
			dataTypeManager.endTransaction(transactionID, true);
		}
	}

	/**
	 * @return all archive search paths (both enabled and disabled are included)
	 */
	private Path[] getArchivePaths() {
		return PathManager.getPathsFromPreferences(DATA_TYPE_ARCHIVE_PATH_KEY, null,
			DISABLED_DATA_TYPE_ARCHIVE_PATH_KEY);
	}

	private FileArchive openFileArchive(String archiveName, UniversalID archiveID,
			boolean acquireWriteLock) {

		if (archiveName.endsWith(FileDataTypeManager.SUFFIX)) {
			archiveName = archiveName.substring(0,
				archiveName.length() - FileDataTypeManager.SUFFIX.length());
		}

		String archiveFileName = archiveName + FileDataTypeManager.SUFFIX;

		List<Archive> allArchives = getAllArchives();
		for (Archive archive : allArchives) {
			if (archive instanceof FileArchive) {
				if (archive.getName().equals(archiveName)) {
					if (archiveID == null ||
						archiveID.equals(archive.getDataTypeManager().getUniversalID())) {
						if (acquireWriteLock && !archive.isModifiable()) {
							// Close archive - hopefully it will get reopened below
							closeArchive(archive);
						}
						break;
					}
				}
			}
		}

		Path[] pathsFromPreferences = getArchivePaths();
		for (Path path : pathsFromPreferences) {
			if (!path.isEnabled() || !isAllowedArchivePath(path.getPathAsString())) {
				continue;
			}
			ResourceFile archiveFile = new ResourceFile(path.getPath(), archiveFileName);
			if (archiveFile.exists()) {
				FileArchive archive = openFileArchive(archiveFile, archiveID, acquireWriteLock);
				if (archive != null) {
					return archive;
				}
			}
		}

		// Look for archive provided with installation (read-only)
		ResourceFile archiveFile = DataTypeArchiveUtility.findArchiveFile(archiveFileName);
		if (archiveFile == null) {
			Msg.showError(this, plugin.getProvider().getComponent(), "Open Archive Failed",
				"Archive file not found: " + archiveFileName);
			return null;
		}
		return openFileArchive(archiveFile, archiveID, false);
	}

	private FileArchive openFileArchive(ResourceFile archiveFile, UniversalID archiveID,
			boolean acquireWriteLock) {
		try {
			FileArchive archive = new FileArchive(this, archiveFile, acquireWriteLock);
			if (archiveID == null ||
				archiveID.equals(archive.getDataTypeManager().getUniversalID())) {
				addArchive(archive);
				return archive;
			}
			archive.close();
		}
		catch (Throwable t) {
			// Show and/or log error
			handleArchiveFileException(plugin, archiveFile, t);
		}
		return null;
	}

	private void openFileArchive(SourceArchive dataTypeSource) {
		if (openFileArchive(dataTypeSource.getName(), dataTypeSource.getSourceArchiveID(),
			false) == null) {
			createInvalidArchiveNode(dataTypeSource);
		}
	}

	public Archive createArchive(File file) {
		try {
			Archive archive = new FileArchive(this, file);
			addArchivePath(new ResourceFile(file));
			addArchive(archive);
			userOpenedFileArchiveNames.add(getSaveableArchive(file.getAbsolutePath()));
			return archive;
		}
		catch (Exception e) {
			Msg.showError(this, plugin.getProvider().getComponent(), "Create Archive Failed",
				"Error creating archive file (" + file.getName() + "): " + e.getMessage());
		}
		return null;
	}

	public Archive createProjectArchive() throws CancelledException {
		CreateDataTypeArchiveDataTreeDialog dialog = getCreateDialog();

		treeDialogCancelled = true;
		tool.showDialog(dialog);
		if (treeDialogCancelled) {
			throw new CancelledException();
		}

		DataTypeArchive dataTypeArchive = dialog.getNewDataTypeArchiveDB();
		Archive archive =
			new ProjectArchive(this, dataTypeArchive, dataTypeArchive.getDomainFile());
		addArchive(archive);
		return archive;
	}

	@SuppressWarnings("unused")
	private void copyArchive(Archive originalArchive, Archive newArchive, TaskMonitor monitor) {
		DataTypeManager originalManager = originalArchive.getDataTypeManager();
		DataTypeManager newManager = newArchive.getDataTypeManager();

		Category originalRoot = originalManager.getRootCategory();
		Category newRoot = newManager.getRootCategory();
		Category[] categories = originalRoot.getCategories();

		monitor.setMessage(
			"Copy Archive " + originalArchive.getName() + " to " + newArchive.getName());
		monitor.initialize(categories.length);

		int transactionID = newManager.startTransaction("Copy Archive");
		try {
			for (Category category : categories) {
				newRoot.copyCategory(category, null, monitor);
				monitor.incrementProgress(1);
			}
			DataType[] dataTypes = originalRoot.getDataTypes();
			for (DataType type : dataTypes) {
				if (monitor.isCancelled()) {
					return;
				}
				newRoot.addDataType(type, null);
			}
		}
		finally {
			newManager.endTransaction(transactionID, true);
		}
	}

	private void openArchives(String[] archiveFilenames) {
		for (String filename : archiveFilenames) {
			String[] projectPathname = DataTypeManagerHandler.parseProjectPathname(filename);
			if (projectPathname != null) {
				DomainFile df =
					plugin.getProjectArchiveFile(projectPathname[0], projectPathname[1]);
				if (df != null) {
					plugin.openArchive(df);
				}
			}
			else {
				File file = new File(filename);
				if (!file.exists()) {
					continue; // if the file does not exist, skip it.
				}
				try {
					openArchive(file, false, false);
				}
				catch (Throwable t) {
					DataTypeManagerHandler.handleArchiveFileException(plugin,
						new ResourceFile(file), t);
				}
			}
		}
	}

	/**
	 * Determine if archive path is allowed.
	 * An attempt is made to disallow any path which appears to be contained
	 * within a Ghidra installation.
	 * @param path directory or file archive path
	 * @return true if path is allowed
	 */
	public boolean isAllowedArchivePath(String path) {

		if (path.startsWith(Path.GHIDRA_HOME)) {
			return false; // Ghidra typeinfo directories will always be searched
		}

		for (String unallowed : UNALLOWED_ARCHIVE_PATH_FRAGMENTS) {
			if (path.indexOf(unallowed) > 0) {
				// Remembering paths to older Ghidra installations is bad
				return false;
			}
		}

		return true;
	}

	private void addArchivePath(ResourceFile archiveFilePath) {

		Path newPath = new Path(archiveFilePath.getParentFile());
		if (!isAllowedArchivePath(newPath.getPathAsString())) {
			return;
		}

		Path[] paths = getArchivePaths();
		for (Path path : paths) {
			if (path.equals(newPath)) {
				if (!path.isEnabled()) {
					path.setEnabled(true);
					PathManager.savePathsToPreferences(DATA_TYPE_ARCHIVE_PATH_KEY,
						DISABLED_DATA_TYPE_ARCHIVE_PATH_KEY, paths);
				}
				return;
			}
		}

		Path[] newPaths = new Path[paths.length + 1];
		System.arraycopy(paths, 0, newPaths, 0, paths.length);
		newPaths[paths.length] = newPath;

		PathManager.savePathsToPreferences(DATA_TYPE_ARCHIVE_PATH_KEY,
			DISABLED_DATA_TYPE_ARCHIVE_PATH_KEY, newPaths);
	}

	public Archive openArchive(File file, boolean acquireWriteLock, boolean isUserAction)
			throws IOException, DuplicateIdException {
		return openArchive(new ResourceFile(file), acquireWriteLock, isUserAction);
	}

	public Archive openArchive(ResourceFile file, boolean acquireWriteLock, boolean isUserAction)
			throws IOException, DuplicateIdException {

		file = file.getCanonicalFile();

		Archive archive = getArchiveForFile(file);
		if (archive == null) {
			archive = new FileArchive(this, file, acquireWriteLock);
			Archive existingArchive =
				findOpenFileArchiveWithID(archive.getDataTypeManager().getUniversalID());
			if (existingArchive != null) {
				archive.close();
				throw new DuplicateIdException(archive.getName(), existingArchive.getName());
			}

			addArchivePath(file);
			addArchive(archive);
		}
		if (isUserAction && (archive instanceof FileArchive)) {
			userOpenedFileArchiveNames.add(getSaveableArchive(file.getAbsolutePath()));
		}
		return archive;
	}

	private Archive findOpenFileArchiveWithID(UniversalID universalID) {
		if (universalID == null) {
			return null;
		}
		List<Archive> allArchives = getAllArchives();
		for (Archive archive : allArchives) {
			if (universalID.equals(archive.getDataTypeManager().getUniversalID())) {
				return archive;
			}
		}
		return null;
	}

	public Archive openArchive(DomainFile domainFile, boolean okToUpgrade, boolean okToRecover,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {

		Archive archive = getArchiveForDomainFile(domainFile);
		if (archive != null) {
			return archive;
		}

		DataTypeArchive dataTypeArchive =
			(DataTypeArchive) domainFile.getDomainObject(tool, okToUpgrade, okToRecover, monitor);
		archive = new ProjectArchive(this, dataTypeArchive, domainFile);
		addArchive(archive);
		return archive;
	}

	public Archive openArchive(DataTypeArchive dataTypeArchive) {
		return openArchive(dataTypeArchive, dataTypeArchive.getDomainFile());
	}

	public Archive openArchive(DataTypeArchive dataTypeArchive, DomainFile domainFile) {
		Archive archive = getArchiveForDomainFile(domainFile);
		if (archive != null) {
			return archive; // already created
		}

		// this file comes to us created from somewhere else, so we must register ourselves as
		// a consumer of this file
		dataTypeArchive.addConsumer(tool);

		archive = new ProjectArchive(this, dataTypeArchive, domainFile);
		addArchive(archive);
		return archive;
	}

	private void createInvalidArchiveNode(SourceArchive sourceArchive) {
		addInvalidArchive(new InvalidFileArchive(this, sourceArchive));
	}

	public DataTypeManager openArchive(String archiveName)
			throws IOException, DuplicateIdException {
		ResourceFile file = DataTypeArchiveUtility.findArchiveFile(archiveName);
		if (file != null) {
			Archive archive = openArchive(file, false, false);
			if (archive != null) {
				return archive.getDataTypeManager();
			}
		}
		return null;
	}

	private Archive getArchiveForFile(ResourceFile file) {
		for (Archive archive : openArchives) {
			if (archive instanceof FileArchive) {
				FileArchive fileArchive = (FileArchive) archive;
				if (file.equals(fileArchive.getFile())) {
					return fileArchive;
				}
			}
		}
		return null;
	}

	private Archive getArchiveForDomainFile(DomainFile domainFile) {
		for (Archive archive : openArchives) {
			if (archive instanceof ProjectArchive) {
				ProjectArchive projectArchive = (ProjectArchive) archive;
				if (domainFile.equals(projectArchive.getDomainFile())) {
					return projectArchive;
				}
			}
		}
		return null;
	}

	private void addArchive(Archive archive) {
		updateArchiveNameInfo(archive);
		openArchives.add(archive);
		archive.getDataTypeManager().addDataTypeManagerListener(listenerDelegate);
		dataTypeIndexer.addDataTypeManager(archive.getDataTypeManager());
		if (!(archive instanceof ProgramArchive)) {
			tool.setConfigChanged(true);
		}
		if (archive instanceof ProjectArchive) {
			String projectPath = getProjectPathname((ProjectArchive) archive, true);
			if (projectPath != null) {
				userOpenedFileArchiveNames.add(projectPath);
			}
		}
		fireArchiveOpened(archive);
	}

	private void updateArchiveNameInfo(Archive archive) {

		DataTypeManager dataTypeManager = archive.getDataTypeManager();
		int transactionID;
		try {
			transactionID =
				dataTypeManager.startTransaction("Update Data Type Source Archive Names");
		}
		catch (Exception e) {
			// can't update now - no big deal
			return;
		}
		try {

			// Notify each open archive about this archives ID and name in case it has changed.
			for (Archive existingArchive : openArchives) {

				if (!existingArchive.isModifiable()) {
					continue;
				}

				DataTypeManager existingDataTypeManager = existingArchive.getDataTypeManager();

				dataTypeManager.updateSourceArchiveName(existingDataTypeManager.getUniversalID(),
					existingDataTypeManager.getName());

				int existingTxID = existingDataTypeManager.startTransaction(
					"Update Data Type Source Archive Name");
				try {
					existingDataTypeManager.updateSourceArchiveName(
						dataTypeManager.getUniversalID(), dataTypeManager.getName());
				}
				finally {
					existingDataTypeManager.endTransaction(existingTxID, true);
				}
			}
		}
		finally {
			dataTypeManager.endTransaction(transactionID, true);
		}
	}

	private boolean isKnownInvalidArchive(SourceArchive sourceArchive) {
		return invalidArchives.get(sourceArchive.getSourceArchiveID()) != null;
	}

	private void addInvalidArchive(InvalidFileArchive archive) {
		invalidArchives.put(archive.getUniversalID(), archive);
		fireArchiveOpened(archive);
	}

	public List<Archive> getAllArchives() {
		return new ArrayList<>(openArchives);
	}

	void archiveClosed(Archive archive) {
		if (archive instanceof InvalidFileArchive) {
			invalidArchives.remove(((InvalidFileArchive) archive).getUniversalID());
		}
		else {
			if (archive instanceof ProjectArchive) {
				((ProjectArchive) archive).getDomainObject().release(tool);
			}
			archive.getDataTypeManager().removeDataTypeManagerListener(listenerDelegate);
			dataTypeIndexer.removeDataTypeManager(archive.getDataTypeManager());
			openArchives.remove(archive);
		}
		tool.setConfigChanged(true);
		fireArchiveClosed(archive);
	}

	void dataTypeManagerChanged(FileArchive archive, DataTypeManager oldManager,
			DataTypeManager newManager) {

		oldManager.removeDataTypeManagerListener(listenerDelegate);
		newManager.addDataTypeManagerListener(listenerDelegate);
		dataTypeIndexer.removeDataTypeManager(oldManager);
		dataTypeIndexer.addDataTypeManager(newManager);
		fireDataTypeManagerChanged(archive);
	}

	public void setRecentlyUsedDataType(DataType dataType) {
		recentlyUsedDataType = new RecentlyUsedDataType(dataType);

	}

	public DataType getRecentlyDataType() {
		return recentlyUsedDataType.getDataType();
	}

	public DataTypeManager getBuiltInDataTypesManager() {
		return builtInDataTypesManager;
	}

	public DataTypeIndexer getDataTypeIndexer() {
		return dataTypeIndexer;
	}

	public void closeAllArchives() {
		// this list will get modified as we close archives, so work from a copy
		Archive[] archives = openArchives.toArray(new Archive[openArchives.size()]);
		for (Archive archive : archives) {
			archive.close();
		}
	}

	public void closeArchive(DataTypeManager dtm) {

		if (dtm instanceof BuiltInDataTypeManager) {
			Msg.info(this, "Cannot close the built-in Data Type Manager");
			return;
		}

		if (dtm instanceof ProgramDataTypeManager) {
			Msg.info(this, "Cannot close the Program's Data Type Manager");
			return;
		}

		Archive archive = getArchive(dtm);
		if (archive == null) {
			Msg.info(this, "Unable close archive; archive not open: '" + dtm.getName() + "'");
		}

		closeArchive(archive);
		Msg.info(this, "Closed archive: '" + archive.getName() + "'");
	}

	private Archive getArchive(DataTypeManager dtm) {
		for (Archive archive : openArchives) {
			DataTypeManager dataTypeManager = archive.getDataTypeManager();
			if (dataTypeManager.equals(dtm)) {
				return archive;
			}
		}
		return null;
	}

	public void closeArchive(Archive archive) {
		DataTypeEditorManager editorManager = DataTypeManagerHandler.this.plugin.getEditorManager();
		editorManager.dismissEditors(archive.getDataTypeManager());

		archive.close(); // this will call us back
	}

	public void removeInvalidArchive(InvalidFileArchive archive) {
		archive.close();

		if (programArchive == null) {
			return;
		}

		ProgramDataTypeManager programDataTypeManager =
			(ProgramDataTypeManager) programArchive.getDataTypeManager();
		Program program = programArchive.getProgram();
		int ID = program.startTransaction("Remove Invalid Source Archive From Program");
		try {
			UniversalID sourceArchiveID = archive.getUniversalID();
			SourceArchive sourceArchive = programDataTypeManager.getSourceArchive(sourceArchiveID);
			if (sourceArchive != null) {
				programDataTypeManager.removeSourceArchive(sourceArchive);
			}
		}
		finally {
			program.endTransaction(ID, true);
		}
	}

	public void addArchiveManagerListener(ArchiveManagerListener listener) {
		archiveManagerlisteners.add(listener);
	}

	public void removeArchiveManagerListener(ArchiveManagerListener listener) {
		archiveManagerlisteners.remove(listener);
	}

	private void fireArchiveOpened(final Archive archive) {
		SystemUtilities.runSwingNow(() -> {
			for (ArchiveManagerListener listener : archiveManagerlisteners) {
				listener.archiveOpened(archive);
			}
		});
	}

	private void fireArchiveClosed(final Archive archive) {
		SystemUtilities.runSwingNow(() -> {
			for (ArchiveManagerListener listener : archiveManagerlisteners) {
				listener.archiveClosed(archive);
			}
		});
	}

	public void fireDataTypeManagerChanged(final FileArchive archive) {
		SystemUtilities.runSwingNow(() -> {
			for (ArchiveManagerListener listener : archiveManagerlisteners) {
				listener.archiveDataTypeManagerChanged(archive);
			}
		});
	}

	public void fireArchiveStateChanged(final Archive archive) {
		SystemUtilities.runSwingNow(() -> {
			for (ArchiveManagerListener listener : archiveManagerlisteners) {
				listener.archiveStateChanged(archive);
			}
		});
	}

	public boolean isInUse(File file) {
		for (Archive archive : openArchives) {
			if (archive instanceof FileArchive) {
				if (file.equals(((FileArchive) archive).getFile().getFile(false))) {
					return true;
				}
			}
		}
		return false;
	}

	public List<Archive> getAllFileOrProjectArchives() {
		List<Archive> archiveList = new ArrayList<>();
		for (Archive archive : openArchives) {
			if (archive instanceof FileArchive || archive instanceof ProjectArchive) {
				archiveList.add(archive);
			}
		}
		return archiveList;
	}

	public List<Archive> getAllModifiedFileArchives() {
		List<Archive> archiveList = new ArrayList<>();
		for (Archive archive : openArchives) {
			if (archive.isModifiable() && archive instanceof FileArchive) {
				archiveList.add(archive);
			}
		}
		return archiveList;
	}

	/**
	 * Returns all favorite DataTypes in all archives.
	 * @return all favorite DataTypes in all archives.
	 */
	public List<DataType> getFavoriteDataTypes() {
		List<DataType> list = new ArrayList<>();
		List<Archive> allArchives = getAllArchives();
		for (Archive archive : allArchives) {
			DataTypeManager dataTypeManager = archive.getDataTypeManager();
			list.addAll(dataTypeManager.getFavorites());
		}

		return list;
	}

	private void initializeFavorites() {

		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(PointerDataType.dataType, null), true);

		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(CharDataType.dataType, null), true);

		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(StringDataType.dataType, null), true);
		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(TerminatedStringDataType.dataType, null), true);
		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(TerminatedUnicodeDataType.dataType, null), true);

		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(FloatDataType.dataType, null), true);
		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(DoubleDataType.dataType, null), true);
		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(LongDoubleDataType.dataType, null), true);

		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(IntegerDataType.dataType, null), true);
		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(LongDataType.dataType, null), true);
		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(UnsignedIntegerDataType.dataType, null), true);
		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(UnsignedLongDataType.dataType, null), true);

		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(ByteDataType.dataType, null), true);
		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(WordDataType.dataType, null), true);
		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(DWordDataType.dataType, null), true);
		builtInDataTypesManager.setFavorite(
			builtInDataTypesManager.resolve(QWordDataType.dataType, null), true);

	}

//==================================================================================================
// Storage Methods
//==================================================================================================

	public void save(SaveState saveState) {
		saveArchiveNames(saveState);
		saveFavorites(saveState);
	}

	public void restore(SaveState saveState) {
		restoreArchiveNames(saveState);
		restoreFavorites(saveState);
	}

	private void saveArchiveNames(SaveState saveState) {
		List<String> openNameList = new ArrayList<>();
		if (knownOpenFileArchiveNames.isEmpty()) {
			for (Archive archive : openArchives) {
				String filePath = null;
				if (archive instanceof FileArchive) {
					FileArchive fileArchive = (FileArchive) archive;
					ResourceFile file = fileArchive.getFile();
					if (file != null) {
						filePath = file.getAbsolutePath();
					}
				}
				else if (archive instanceof ProjectArchive) {
					filePath = getProjectPathname((ProjectArchive) archive, true);
				}
				if (filePath != null) {
					openNameList.add(filePath);
				}
			}
		}
		else {
			openNameList.addAll(knownOpenFileArchiveNames);
		}
		saveState.putStrings(ARCHIVE_NAMES, getSaveableArchiveNames(openNameList));

		List<String> recentMenuList = new ArrayList<>();
		Collection<String> recentlyOpenedArchives = plugin.getRecentlyOpenedArchives();
		for (String file : recentlyOpenedArchives) {
			recentMenuList.add(file);
		}
		saveState.putStrings(RECENT_NAMES, getSaveableArchiveNames(recentMenuList));

		// update the initialArchives list so that future checks on that list do not trigger a 
		// state change
		initiallyOpenedFileArchiveNames = getOpenFileArchiveNames(openArchives);
	}

	private String[] getSaveableArchiveNames(List<String> absoluteFilenameList) {
		String[] saveableFilenames = new String[absoluteFilenameList.size()];
		for (int i = 0; i < absoluteFilenameList.size(); i++) {
			saveableFilenames[i] = getSaveableArchive(absoluteFilenameList.get(i));
		}
		return saveableFilenames;
	}

	private String getSaveableArchive(String absoluteFilename) {
		if (absoluteFilename.startsWith(PROJECT_NAME_DELIMETER)) {
			return absoluteFilename;
		}
		Path path = new Path(absoluteFilename);
		return path.getPathAsString();
	}

	private void restoreArchiveNames(SaveState saveState) {
		String[] savedFilenames = saveState.getStrings(ARCHIVE_NAMES, new String[0]);
//        for (int i = 0 ; i < savedFilenames.length ; ++i) {
//        	savedFilenames[i] = StringUtilities.fixupPathSeparator(savedFilenames[i]);
//        }
		String[] filenames = getAbsoluteArchiveNames(savedFilenames);

		openArchives(filenames);

		String[] recentFilenames = saveState.getStrings(RECENT_NAMES, null);
		filenames = getAbsoluteArchiveNames(recentFilenames);
		for (String filename : filenames) {
			if (filename.startsWith(PROJECT_NAME_DELIMETER)) {
				String[] projectPathname = parseProjectPathname(filename);
				if (projectPathname != null) {
					plugin.addRecentlyOpenedProjectArchive(projectPathname[0], projectPathname[1]);
				}
			}
			else {
				ResourceFile file = new ResourceFile(filename);
				if (file.exists()) {
					file = file.getCanonicalFile();
					plugin.addRecentlyOpenedArchiveFile(file);
				}
			}
		}

		for (String filename : savedFilenames) {
			initiallyOpenedFileArchiveNames.add(filename);
		}
		userOpenedFileArchiveNames = new HashSet<>();
		knownOpenFileArchiveNames = new HashSet<>();
	}

	/**
	 * Determine if we can remember the specified project archive using a simple project path
	 * (e.g., we can't remember specific versions). 
	 * @param pa project archive
	 * @param activeProjectOnly if true pa must be contained within the 
	 * active project to be remembered.
	 * @return return project path which can be remembered or null 
	 */
	public String getProjectPathname(ProjectArchive pa, boolean activeProjectOnly) {
		// Project archives are always opened by a user.
		// Only remember it if it is the current version within the current project
		DomainFile df = pa.getDomainObject().getDomainFile();
		ProjectLocator projectLocator = df.getProjectLocator();
		String projectName = projectLocator.getName();
		String dfProjectName = projectName;
		boolean remember = df.isInWritableProject();
		if (!remember) {
			// handle read-only case
			Project project = tool.getProjectManager().getActiveProject();
			remember = (project != null && project.getName().equals(dfProjectName) &&
				df.getVersion() == DomainFile.DEFAULT_VERSION);
		}
		return remember ? getProjectPathname(projectName, df.getPathname()) : null;
	}

	private static String[] getAbsoluteArchiveNames(String[] saveableFilenames) {
		if (saveableFilenames == null) {
			return new String[0];
		}
		List<String> absoluteFilenameList = new ArrayList<>();
		for (String filename : saveableFilenames) {
			try {
				filename = filename.startsWith(PROJECT_NAME_DELIMETER) ? filename
						: getAbsoluteArchive(filename);
				absoluteFilenameList.add(filename);
			}
			catch (FileNotFoundException e) {
				Msg.error(DataTypeManagerHandler.class, e.getMessage());
			}
		}
		String[] absoluteFilenames = new String[absoluteFilenameList.size()];
		for (int i = 0; i < absoluteFilenames.length; i++) {
			absoluteFilenames[i] = absoluteFilenameList.get(i);
		}
		return absoluteFilenames;
	}

	private static String getAbsoluteArchive(String saveableFilename) throws FileNotFoundException {
		if (saveableFilename.startsWith(RELATIVE_PATH_PREFIX)) {
			ResourceFile file = DataTypeArchiveUtility.findArchiveFile(saveableFilename);
			if (file == null) {
				throw new FileNotFoundException("Archive not found: " + saveableFilename);
			}
			return file.getAbsolutePath();
		}
		Path path = new Path(saveableFilename);
		return path.getPath().getAbsolutePath();
	}

	void saveFavorites(SaveState saveState) {
		List<DataType> favoritesList = builtInDataTypesManager.getFavorites();
		String[] names = new String[favoritesList.size()];
		for (int i = 0; i < names.length; i++) {
			DataType dataType = favoritesList.get(i);
			names[i] = dataType.getPathName();
		}

		saveState.putStrings(FAVORITES, names);
	}

	void restoreFavorites(SaveState saveState) {
		String[] names = saveState.getStrings(FAVORITES, new String[0]);
		if (names.length == 0) {
			return;
		}
		Set<DataType> favorites = new HashSet<>();
		for (String name : names) {
			DataType dataType = builtInDataTypesManager.getDataType(name);
			if (dataType != null) {
				favorites.add(dataType);
			}
		}

		List<DataType> currentFavoritesList = builtInDataTypesManager.getFavorites();
		for (DataType type : currentFavoritesList) {
			if (favorites.contains(type)) {
				favorites.remove(type);
			}
			else {
				builtInDataTypesManager.setFavorite(type, false);
			}
		}
		for (DataType dataType : favorites) {
			builtInDataTypesManager.setFavorite(dataType, true);
		}
	}

	class RecentlyUsedDataType {

		private String dataTypeManagerName;
		private CategoryPath path;
		private String dataTypeName;

		RecentlyUsedDataType() {
			// default constructor
		}

		RecentlyUsedDataType(DataType dt) {
			dataTypeName = dt.getName();
			path = dt.getCategoryPath();
			DataTypeManager dtMgr = dt.getDataTypeManager();
			dataTypeManagerName = dtMgr == null ? null : dtMgr.getName();

			if (dataTypeManagerName == null && programArchive != null) {
				DataTypeManager programDataTypeManager = programArchive.getDataTypeManager();
				dataTypeManagerName = programDataTypeManager.getName();
			}
		}

		public DataType getDataType() {
			if (dataTypeName == null) {
				return null;
			}
			DataTypeManager dtMgr = findDataTypeManager();
			Category category = dtMgr.getCategory(path);
			if (category != null) {
				DataType dt = category.getDataType(dataTypeName);
				if (dt != null) {
					return dt;
				}
			}
			return getBuiltInDataType();
		}

		private DataType getBuiltInDataType() {
			DataTypeManager dtMgr = getBuiltInDataTypesManager();
			Category category = dtMgr.getCategory(path);
			if (category != null) {
				DataType dt = category.getDataType(dataTypeName);
				if (dt != null) {
					return dt;
				}
			}
			return null;
		}

		private DataTypeManager findDataTypeManager() {
			for (Archive archive : openArchives) {
				if (archive.getName().equals(dataTypeManagerName)) {
					return archive.getDataTypeManager();
				}
			}
			return builtInDataTypesManager;
		}
	}

	public DataTypeManager[] getDataTypeManagers() {
		DataTypeManager[] managers = new DataTypeManager[openArchives.size()];
		for (int i = 0; i < managers.length; i++) {
			managers[i] = openArchives.get(i).getDataTypeManager();
		}
		return managers;
	}

	public void addDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		dataTypeManagerListeners.add(listener);
	}

	public void removeDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		dataTypeManagerListeners.remove(listener);
	}

	class DataTypeManagerListenerDelegate implements DataTypeManagerChangeListener {

		@Override
		public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.categoryAdded(dtm, path);
			}
		}

		@Override
		public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.categoryMoved(dtm, oldPath, newPath);
			}
		}

		@Override
		public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.categoryRemoved(dtm, path);
			}
		}

		@Override
		public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath,
				CategoryPath newPath) {
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.categoryRenamed(dtm, oldPath, newPath);
			}
		}

		@Override
		public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.dataTypeAdded(dtm, path);
			}
		}

		@Override
		public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.dataTypeChanged(dtm, path);
			}
		}

		@Override
		public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.dataTypeMoved(dtm, oldPath, newPath);
			}
		}

		@Override
		public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.dataTypeRemoved(dtm, path);
			}
		}

		@Override
		public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath) {
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.dataTypeRenamed(dtm, oldPath, newPath);
			}
		}

		@Override
		public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath, DataType newDataType) {
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.dataTypeReplaced(dtm, oldPath, newPath, newDataType);
			}
		}

		@Override
		public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.favoritesChanged(dtm, path, isFavorite);
			}
		}

		@Override
		public void sourceArchiveAdded(DataTypeManager dataTypeManager,
				SourceArchive dataTypeSource) {
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.sourceArchiveAdded(dataTypeManager, dataTypeSource);
			}
		}

		@Override
		public void sourceArchiveChanged(DataTypeManager dataTypeManager,
				SourceArchive dataTypeSource) {
			for (DataTypeManagerChangeListener listener : dataTypeManagerListeners) {
				listener.sourceArchiveChanged(dataTypeManager, dataTypeSource);
			}
		}
	}

	/**
	 * Signals to this manager to save the knowledge of all currently opened archives and to mark 
	 * the tool as dirty (changed) if the current open archives are not the same as those that
	 * were initially opened.
	 */
	public void updateKnownOpenArchives() {
		knownOpenFileArchiveNames = getOpenFileArchiveNames(openArchives);
		if (!knownOpenFileArchiveNames.equals(initiallyOpenedFileArchiveNames)) {
			tool.setConfigChanged(true);
		}
	}

	private Set<String> getOpenFileArchiveNames(List<Archive> archives) {
		Set<String> newSet = new HashSet<>();
		for (Archive archive : archives) {
			String filePath = null;
			if (archive instanceof FileArchive) {
				ResourceFile file = ((FileArchive) archive).getFile();
				if (file != null) {
					filePath = getSaveableArchive(file.getAbsolutePath());
				}
			}
			else if (archive instanceof ProjectArchive) {
				filePath = getProjectPathname((ProjectArchive) archive, true);
			}
			if (filePath != null && (initiallyOpenedFileArchiveNames.contains(filePath) ||
				userOpenedFileArchiveNames.contains(filePath))) {
				newSet.add(filePath);
			}
		}
		return newSet;
	}

	public Set<String> getPossibleEquateNames(long value) {
		Set<String> equateNames = new HashSet<>();
		for (Archive element : openArchives) {
			DataTypeManager dtMgr = element.getDataTypeManager();
			dtMgr.findEnumValueNames(value, equateNames);
		}
		return equateNames;

	}

	public void save(UndoableDomainObject undoableDomainObject) {

		tool.prepareToSave(undoableDomainObject);
		if (acquireSaveLock(undoableDomainObject)) {

			try {
				DomainFileSaveTask task = new DomainFileSaveTask(CONTENT_NAME,
					undoableDomainObject.getDomainFile(), tool);
				new TaskLauncher(task, tool.getToolFrame());
			}
			finally {
				undoableDomainObject.unlock();
			}
		}
	}

	public void saveAs(UndoableDomainObject undoableDomainObject) {
		if (!getSaveAsLock(undoableDomainObject)) {
			return;
		}
		try {
			DataTreeDialog dialog = getSaveDialog();
//			dialog.setNameText(undoableDomainObject.getDomainFile().getName());
			treeDialogCancelled = true;
			tool.showDialog(dialog);
			if (!treeDialogCancelled) {
				saveAs(undoableDomainObject, dialog.getDomainFolder(), dialog.getNameText());
			}
		}
		finally {
			undoableDomainObject.unlock();
		}
	}

	private void saveAs(UndoableDomainObject undoableDomainObject, DomainFolder folder,
			String name) {
		DomainFile existingFile = folder.getFile(name);
		if (existingFile == undoableDomainObject.getDomainFile()) {
			save(undoableDomainObject);
			return;
		}
		if (existingFile != null) {
			String msg = "Program " + name + " already exists.\n" + "Do you want to overwrite it?";
			if (OptionDialog.showOptionDialog(tool.getToolFrame(), "Duplicate Name", msg,
				"Overwrite", OptionDialog.QUESTION_MESSAGE) == OptionDialog.CANCEL_OPTION) {
				return;
			}
		}
		tool.prepareToSave(undoableDomainObject);
		DomainObjectSaveAsTask task = new DomainObjectSaveAsTask(CONTENT_NAME, undoableDomainObject,
			folder, name, existingFile != null);
		new TaskLauncher(task, tool.getToolFrame());
	}

	private boolean acquireSaveLock(UndoableDomainObject undoableDomainObject) {
		if (!undoableDomainObject.lock(null)) {
			String title = "Save " + CONTENT_NAME + " (Busy)";
			StringBuilder buf = new StringBuilder();
			buf.append("The " + CONTENT_NAME + " is currently being modified by \n");
			buf.append("the following actions:\n ");
			Transaction t = undoableDomainObject.getCurrentTransaction();
			List<String> list = t.getOpenSubTransactions();
			Iterator<String> it = list.iterator();
			while (it.hasNext()) {
				buf.append("\n     ");
				buf.append(it.next());
			}
			buf.append("\n \n");
			buf.append(
				"WARNING! The above task(s) should be cancelled before attempting a Save.\n");
			buf.append("Only proceed if unable to cancel them.\n \n");
			buf.append(
				"If you continue, all changes made by these tasks, as well as any other overlapping task,\n");
			buf.append(
				"will be LOST and subsequent transaction errors may occur while these tasks remain active.\n \n");

			int result = OptionDialog.showOptionDialog(tool.getToolFrame(), title, buf.toString(),
				"Save Archive!", OptionDialog.WARNING_MESSAGE);

			if (result == OptionDialog.OPTION_ONE) {
				undoableDomainObject.forceLock(true, "Save Archive");
				return true;
			}
			return false;
		}
		return true;
	}

	private boolean getSaveAsLock(UndoableDomainObject undoableDomainObject) {
		if (!undoableDomainObject.lock(null)) {
			String title = "Save " + CONTENT_NAME + " As (Busy)";
			StringBuffer buf = new StringBuffer();
			buf.append("The " + CONTENT_NAME +
				" is currently being modified by the following actions/tasks:\n \n");
			Transaction t = undoableDomainObject.getCurrentTransaction();
			List<String> list = t.getOpenSubTransactions();
			Iterator<String> it = list.iterator();
			while (it.hasNext()) {
				buf.append("\n     ");
				buf.append(it.next());
			}
			buf.append("\n \n");
			buf.append(
				"WARNING! The above task(s) should be cancelled before attempting a Save As...\n");
			buf.append("Only proceed if unable to cancel them.\n \n");
			buf.append(
				"If you click 'Save Archive As (Rollback)' {recommended}, all changes made\n");
			buf.append("by these tasks, as well as any other overlapping task, will be LOST!\n");
			buf.append(
				"If you click 'Save As (As Is)', the archive will be saved in its current\n");
			buf.append("state which may contain some incomplete data.\n");
			buf.append("Any forced save may also result in subsequent transaction errors while\n");
			buf.append("the above tasks remain active.\n ");

			int result = OptionDialog.showOptionDialog(tool.getToolFrame(), title, buf.toString(),
				"Save Archive As (Rollback)!", "Save Archive As (As Is)!",
				OptionDialog.WARNING_MESSAGE);

			if (result == OptionDialog.OPTION_ONE) {
				undoableDomainObject.forceLock(true, "Save Archive As");
				return true;
			}
			else if (result == OptionDialog.OPTION_TWO) {
				undoableDomainObject.forceLock(false, "Save Archive As");
				return true;
			}
			return false;
		}
		return true;
	}

	private DataTreeDialog getSaveDialog() {
		if (dataTreeSaveDialog == null) {

			ActionListener listener = event -> {
				DomainFolder folder = dataTreeSaveDialog.getDomainFolder();
				String newName = dataTreeSaveDialog.getNameText();
				if (newName.length() == 0) {
					dataTreeSaveDialog.setStatusText("Please enter a name");
					return;
				}
				else if (folder == null) {
					dataTreeSaveDialog.setStatusText("Please select a folder");
					return;
				}

				DomainFile file = folder.getFile(newName);
				if (file != null && file.isReadOnly()) {
					dataTreeSaveDialog.setStatusText("Read Only.  Choose new name/folder");
				}
				else {
					dataTreeSaveDialog.close();
					treeDialogCancelled = false;
				}
			};
			dataTreeSaveDialog =
				new DataTreeDialog(null, "Save As", DataTreeDialog.SAVE, domainFileFilter);

			dataTreeSaveDialog.addOkActionListener(listener);
			dataTreeSaveDialog.setHelpLocation(
				new HelpLocation(HelpTopics.PROGRAM, "Save_As_File"));
		}
		return dataTreeSaveDialog;
	}

	private CreateDataTypeArchiveDataTreeDialog getCreateDialog() {
		if (dataTreeCreateDialog == null) {

			ActionListener listener = event -> {
				DomainFolder folder = dataTreeCreateDialog.getDomainFolder();
				String newName = dataTreeCreateDialog.getNameText();
				if (newName.length() == 0) {
					dataTreeCreateDialog.setStatusText("Please enter a name");
					return;
				}
				else if (folder == null) {
					dataTreeCreateDialog.setStatusText("Please select a folder");
					return;
				}

				DomainFile file = folder.getFile(newName);
				if (file != null) {
					dataTreeCreateDialog.setStatusText("Choose a name that doesn't exist.");
					return;
				}

				if (!dataTreeCreateDialog.createNewDataTypeArchive()) {
					return;
				}

				// everything is OK
				dataTreeCreateDialog.close();
				treeDialogCancelled = false;
			};

			dataTreeCreateDialog = new CreateDataTypeArchiveDataTreeDialog(null, "Create",
				DataTreeDialog.CREATE, domainFileFilter);

			dataTreeCreateDialog.addOkActionListener(listener);
			dataTreeCreateDialog.setHelpLocation(
				new HelpLocation(HelpTopics.DATA_MANAGER, "Create_Data_Type_Archive"));
		}
		return dataTreeCreateDialog;
	}

	public DataTypeManager getDataTypeManager(SourceArchive source) {
		List<Archive> allArchives = getAllArchives();
		for (Archive archive : allArchives) {
			DataTypeManager dataTypeManager = archive.getDataTypeManager();
			UniversalID universalID = dataTypeManager.getUniversalID();
			if ((universalID != null) && universalID.equals(source.getSourceArchiveID())) {
				return dataTypeManager;
			}
		}
		return null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class CreateDataTypeArchiveDataTreeDialog extends DataTreeDialog {

		private DataTypeArchiveDB dataTypeArchiveDB;

		CreateDataTypeArchiveDataTreeDialog(Component parent, String title, int type,
				DomainFileFilter filter) {
			super(parent, title, type, filter);
		}

		/**
		 * Callback method to create the DB and to show errors if they happen.
		 */
		boolean createNewDataTypeArchive() {
			dataTypeArchiveDB = null;
			DomainFolder domainFolder = getDomainFolder();
			String archiveName = getNameText();
			try {
				// try to create the archive to make sure we don't get any exceptions
				dataTypeArchiveDB = new DataTypeArchiveDB(domainFolder, archiveName, tool);
				return true;
			}
			catch (DuplicateNameException e) {
				dataTreeCreateDialog.setStatusText("Duplicate Name: " + e.getMessage());
			}
			catch (InvalidNameException e) {
				dataTreeCreateDialog.setStatusText("Invalid Name: " + e.getMessage());
			}
			catch (IOException e) {
				dataTreeCreateDialog.setStatusText("Unexpected IOException!");
				Msg.showError(null, dataTreeCreateDialog.getComponent(), "Unexpected Exception",
					e.getMessage(), e);
			}

			return false;
		}

		DataTypeArchiveDB getNewDataTypeArchiveDB() {
			return dataTypeArchiveDB;
		}
	}

	static class DomainFileSaveTask extends Task {

		private String domainObjectType;
		private DomainFile domainFile;
		private PluginTool pluginTool;

		/**
		 * Construct new SaveFileTask.
		 * @param df domain file to save
		 */
		DomainFileSaveTask(String domainObjectType, DomainFile df, PluginTool tool) {
			super("Save " + domainObjectType, true, true, true);
			this.domainObjectType = domainObjectType;
			this.domainFile = df;
			this.pluginTool = tool;
		}

		/**
		 * @see ghidra.util.task.Task#run(TaskMonitor)
		 */
		@Override
		public void run(TaskMonitor monitor) {
			monitor.setMessage("Saving " + domainObjectType + "...");
			try {
				domainFile.save(monitor);
			}
			catch (CancelledException e) {
				// O.K., expected
			}
			catch (NotConnectedException e) {
				ClientUtil.promptForReconnect(pluginTool.getProject().getRepository(),
					pluginTool.getToolFrame());
			}
			catch (ConnectException e) {
				ClientUtil.promptForReconnect(pluginTool.getProject().getRepository(),
					pluginTool.getToolFrame());
			}
			catch (IOException e) {
				ClientUtil.handleException(pluginTool.getProject().getRepository(), e, "Save File",
					pluginTool.getToolFrame());
			}
		}
	}

	static class DomainObjectSaveAsTask extends Task {

		private String domainObjectType;
		private UndoableDomainObject domainObject;
		private DomainFolder parentFolder;
		private String newName;
		private boolean doOverwrite;

		/**
		 * Construct new SaveProjectArchiveTask to do a "Save As"
		 * @param domainObjectType
		 * @param domainObject
		 * @param folder new parent folder
		 * @param newName name for domain object
		 * @param doOverwrite true means the given name already exists and the user
		 * wants to overwrite that existing file; false means a new file will 
		 * get created
		 */
		DomainObjectSaveAsTask(String domainObjectType, UndoableDomainObject domainObject,
				DomainFolder folder, String newName, boolean doOverwrite) {

			super("Save " + domainObjectType + " As", true, true, true);
			this.domainObjectType = domainObjectType;
			this.domainObject = domainObject;
			this.parentFolder = folder;
			this.newName = newName;
			this.doOverwrite = doOverwrite;
		}

		/**
		 * @see ghidra.util.task.Task#run(TaskMonitor)
		 */
		@Override
		public void run(TaskMonitor monitor) {
			monitor.setMessage("Saving " + domainObjectType + "...");
			try {
				if (doOverwrite) {
					DomainFile df = parentFolder.getFile(newName);
					df.delete();
				}
				parentFolder.createFile(newName, domainObject, monitor);
			}
			catch (IOException e) {
				Msg.showError(this, null, "Error Overwriting " + domainObjectType, e.getMessage(),
					e);
			}
			catch (InvalidNameException e) {
				Msg.showError(this, null, "Invalid Name", e.getMessage(), e);
			}
			catch (Throwable e) {
				Msg.showError(this, null, "Error", e.getMessage(), e);
			}
		}
	}

	private class MyFolderListener extends DomainFolderListenerAdapter {

		@Override
		public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
			if (!DataTypeArchiveContentHandler.DATA_TYPE_ARCHIVE_CONTENT_TYPE.equals(
				file.getContentType())) {
				return;
			}
			Iterator<Archive> archiveIter = openArchives.iterator();
			while (archiveIter.hasNext()) {
				Archive archive = archiveIter.next();
				if (archive instanceof ProjectArchive) {
					ProjectArchive projectArchive = (ProjectArchive) archive;
					DomainFile domainFile = projectArchive.getDomainFile();
					if (file.equals(domainFile) && !projectArchive.isModifiable() &&
						file.isCheckedOut()) {
						replaceArchiveWithFile(projectArchive, file);
						return;
					}
				}
			}
		}

		@Override
		public void domainFileRemoved(DomainFolder parentFolder, String name, String fileID) {
			// DT What if anything needs to be done here?
//			Iterator<Archive> archiveIter = openArchives.iterator();
//			while (archiveIter.hasNext()) {
//				Archive archive = archiveIter.next();
//				if (archive instanceof ProjectArchive) {
//					ProjectArchive projectArchive = (ProjectArchive) archive;
//					DomainFile domainFile = projectArchive.getDomainFile();
//					if (StringUtilities.equals(domainFile.getFileID(), fileID)) {
//						// DT What if anything needs to be done here?
//						return;
//					}
//				}
//			}
		}

		@Override
		public void domainFileObjectReplaced(DomainFile file, DomainObject oldObject) {
			if (oldObject instanceof DataTypeArchiveDB) {
				Iterator<Archive> archiveIter = openArchives.iterator();
				while (archiveIter.hasNext()) {
					Archive archive = archiveIter.next();
					if (archive instanceof ProjectArchive) {
						ProjectArchive projectArchive = (ProjectArchive) archive;
						DomainObject domainObject = projectArchive.getDomainObject();
						if (domainObject == oldObject) {
							replaceArchiveWithFile(projectArchive, file);
							return;
						}
					}
				}
			}
		}

		@Override
		public void domainFileRenamed(DomainFile file, String oldName) {
			if (!DataTypeArchiveContentHandler.DATA_TYPE_ARCHIVE_CONTENT_TYPE.equals(
				file.getContentType())) {
				return;
			}
			String newName = file.getName();
			String fileID = file.getFileID();
			Iterator<Archive> archiveIter = openArchives.iterator();
			while (archiveIter.hasNext()) {
				Archive archive = archiveIter.next();
				if (!archive.isModifiable()) {
					continue;
				}
				DataTypeManager dataTypeManager = archive.getDataTypeManager();
				updateSourceArchiveName(dataTypeManager, fileID, newName);
			}
		}

		private void replaceArchiveWithFile(ProjectArchive projectArchive,
				DomainFile newDomainFile) {
			DomainFile archiveDomainFile = projectArchive.getDomainFile();
			DomainObject archiveDomainObject = projectArchive.getDomainObject();
			DomainFile objectDomainFile = archiveDomainObject.getDomainFile();
			if (archiveDomainFile == objectDomainFile) {
				return;
			}

			closeArchive(projectArchive);

			String contentType = null;
			try {
				contentType = newDomainFile.getContentType();
				try {
					openArchive(newDomainFile, false, false, TaskMonitorAdapter.DUMMY_MONITOR);
				}
				catch (VersionException e) {
					// should never happen following check-in (i.e., DomainObjectReplaced)
					if (VersionExceptionHandler.isUpgradeOK(null, newDomainFile, "Re-open", e)) {
						openArchive(newDomainFile, true, false, TaskMonitorAdapter.DUMMY_MONITOR);
					}
				}
			}
			catch (VersionException e) {
				VersionExceptionHandler.showVersionError(null, newDomainFile.getName(), contentType,
					"Re-open", e);
			}
			catch (CancelledException e) {
				throw new AssertException(e);
			}
			catch (Exception e) {
				if (newDomainFile.isInWritableProject() && (e instanceof IOException)) {
					RepositoryAdapter repo =
						newDomainFile.getParent().getProjectData().getRepository();
					ClientUtil.handleException(repo, e, "Re-open File", null);
				}
				else {
					Msg.showError(this, null, "Error Opening " + newDomainFile.getName(),
						"Opening data type archive failed.\n" + e.getMessage());
				}
			}
		}
	}

	//==================================================================================================
	// Static Methods
	//==================================================================================================

	/**
	 * Provides an exception handler for a failed attempt to open an datatype archive file.
	 * This method will display exception information to the user and/or log. 
	 * @param plugin datatype manager plugin
	 * @param archiveFile archive file resource being opened
	 * @param t throwable
	 */
	public static void handleArchiveFileException(DataTypeManagerPlugin plugin,
			ResourceFile archiveFile, Throwable t) {
		if (t instanceof FileNotFoundException) {
			Msg.showError(plugin, plugin.getProvider().getComponent(), "File Not Found",
				archiveFile.getAbsolutePath() + " not found!");
		}
		else if (t instanceof IOException) {
			Throwable cause = t.getCause();
			if (cause instanceof VersionException) {
				VersionExceptionHandler.showVersionError(null, archiveFile.getName(), "Archive",
					"open", (VersionException) cause);
			}
			else {
				Msg.showError(plugin, plugin.getProvider().getComponent(), "Open Archive Failed",
					t.getMessage() + ": " + archiveFile.getName());
			}
		}
		else if (t instanceof DuplicateIdException) {
			DuplicateIdException dupIdExc = (DuplicateIdException) t;
			Msg.showError(plugin, plugin.getProvider().getComponent(), "Duplicate Archive ID Error",
				"Attempted to open a datatype archive with the same ID as datatype archive that is " +
					"already open. " + dupIdExc.getNewArchiveName() + " has same id as " +
					dupIdExc.getExistingArchiveName());
		}
		else {
			Msg.showError(plugin, plugin.getProvider().getComponent(), "Open Archive Failed",
				"Unexpected exception opening archive: " + archiveFile.getName(), t);
		}
	}

	/**
	 * Create project archive path string for recently used project archive
	 * @param projectName
	 * @param pathname
	 * @return recently used project pathname string
	 */
	public static String getProjectPathname(String projectName, String pathname) {
		if (pathname.length() < 2 || !pathname.startsWith(FileSystem.SEPARATOR)) {
			throw new IllegalArgumentException("Absolute project pathname required");
		}
		return PROJECT_NAME_DELIMETER + projectName + PROJECT_NAME_DELIMETER + pathname;
	}

	/**
	 * Parse a recently used project pathname string
	 * @param projectFilePath project pathname string
	 * @return 2-element String array containing project name and pathname of project archive, or null if path is invalid
	 */
	public static String[] parseProjectPathname(String projectFilePath) {
		if (projectFilePath.startsWith(PROJECT_NAME_DELIMETER)) {
			int index = projectFilePath.indexOf(PROJECT_NAME_DELIMETER, 1);
			if (index > 0) {
				String projectName = projectFilePath.substring(1, index);
				String pathname = projectFilePath.substring(index + 1);
				if (pathname.length() > 1 && pathname.startsWith(FileSystem.SEPARATOR)) {
					return new String[] { projectName, pathname };
				}
			}
		}
		return null;
	}
}

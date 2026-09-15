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

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Set;

import docking.widgets.pathmanager.PathManager;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeState;
import generic.jar.ResourceFile;
import generic.util.Path;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.plugin.core.datamgr.archive.InvalidArchive;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.services.Recover;
import ghidra.app.services.Upgrade;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.dtarchive.DataTypeArchiveContentHandler;
import ghidra.program.database.dtarchive.DataTypeArchiveFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.UniversalID;
import ghidra.util.exception.*;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * Helper class to create, open, and close DataTypeArchives. Internally, it uses an 
 * {@link ActiveDataTypeStores} to track all open archives in the tool, maintain a
 * complete index of all datatypes open, and remember which archives should be automatically
 * opened when the tool is re-launched.
 */
public class ArchiveManager {
	private static final String[] UNALLOWED_ARCHIVE_PATH_FRAGMENTS = new String[] {
		"/Ghidra/Extensions/", "/Ghidra/docs/", "/Ghidra/Features/", "/Ghidra/Test/" };

	public static final String OLD_DATA_TYPE_ARCHIVE_PATH_KEY = "DATA_TYPE_ARCHIVE_PATH";
	public static final String DATA_TYPE_ARCHIVE_PATH_KEY = "DATATYPE_ARCHIVE_PATHS";
	public static final String DISABLED_DATA_TYPE_ARCHIVE_PATH_KEY =
		"DISABLED_DATA_TYPE_ARCHIVE_PATH";

	private ActiveDataTypeStores openStores;
	private DataTypeManagerPlugin plugin;
	private MyFolderListener folderListener;

	public ArchiveManager(DataTypeManagerPlugin plugin) {
		this.plugin = plugin;
		openStores = new ActiveDataTypeStores();
		initializeFavorites();

		folderListener = new MyFolderListener();
		PluginTool tool = plugin.getTool();
		Project project = tool.getProject();
		project.getProjectData().addDomainFolderChangeListener(folderListener);
	}

	/**
	 * Close and reopen the given archive, preserving the tree selection
	 * @param archive the archive to reopen
	 * @return the reopened archive instance. The old instance is now invalid
	 */
	public PersistentDataTypeArchive reopenArchive(PersistentDataTypeArchive archive) {
		if (archive instanceof FileDataTypeArchive fileArchive) {
			boolean changeable = fileArchive.isChangeable();
			return reopenFileArchive(fileArchive, changeable);
		}
		else if (archive instanceof ProjectDataTypeArchive projectArchive) {
			return doReopenProjectArchive(projectArchive);
		}
		return null;
	}

	/**
	 * Close and reopen the given FileDataTypeArchive in either update or read-only mode. If going
	 * from read-only to open for update fails, it will attempt to keep it open read-only (It closed
	 * the read-only version before attempt to open it for update.)
	 * @param archive the archive to reopen
	 * @param forUpdate whether or not the archive is modifiable
	 * @return the new archive instance that was reopened
	 */
	public FileDataTypeArchive reopenFileArchive(FileDataTypeArchive archive, boolean forUpdate) {
		GTreeState treeState = getTreeState();
		ResourceFile file = archive.getFile();
		boolean rememberInTool = false;
		if (openStores.contains(archive)) {
			rememberInTool = openStores.isRemembered(archive);
			openStores.removeArchive(archive);
		}
		FileDataTypeArchive reopenedArchive = null;
		reopenedArchive = openFileArchiveInTask(file, forUpdate, Upgrade.ASK, rememberInTool);
		if (reopenedArchive == null && forUpdate) {
			// Open for update failed - try re-open as read-only
			reopenedArchive = openFileArchiveInTask(file, false, Upgrade.NO, rememberInTool);
		}
		restoreTreeState(treeState);
		return reopenedArchive;
	}

	/**
	 * Called when the tool is closed
	 */
	public void dispose() {
		PluginTool tool = plugin.getTool();
		Project project = tool.getProject();
		ProjectData projectData = project.getProjectData();
		projectData.removeDomainFolderChangeListener(folderListener);
		openStores.dispose();
	}

	/**
	 * {@return a list of all archives that have been marked that they should be re-opened when
	 * the tool is re-launched}
	 */
	public Set<PersistentDataTypeArchive> getRememberedArchives() {
		return openStores.getRememberedArchives();
	}

	/**
	 * Creates a new ProjectDataTypeArchive. The user will be prompted for the folder and name
	 * of the new archive.
	 * @return the newly created ProjectDaaTypeArchive
	 */
	public ProjectDataTypeArchive createProjectArchive() {
		CreateProjectArchiveDialog dialog = new CreateProjectArchiveDialog(this);

		plugin.getTool().showDialog(dialog);
		ProjectDataTypeArchive archive = dialog.getArchive();
		if (archive != null) {
			openStores.addArchive(archive, true);
			archive.release(this);
		}
		return archive;
	}

	/**
	 * Opens the give DomainFile in the tool as a ProjectDataTypeArchive. This method should be
	 * used by clients that are already in the background and have a TaskMonitor that can be
	 * used to cancel the operation.
	 * @param file the DomainFile to open
	 * @param version the version (if the file is versioned, otherwise use DomainFile.DEFAULT_VERSION)
	 * @param upgradeStrategy determine what happens if the archive needs to be upgraded before
	 * opening. The options are to do the upgrade, don't do the upgrade, or ask which pops up a 
	 * dialog asking if it is ok to upgrade.
	 * @param recoverStrategy determine what happens if the archive has crash recovery data. The
	 * options are to recover the crash data changes, not recover the changes, or to ask which
	 * popups a dialog asking if the crash recovery data should be used.
	 * @param rememberInTool specifies if this archive should be remembered to be opened the next
	 * time the tool is launched.
	 * @param monitor The task monitor that can be used to cancel the operation
	 * @return new newly opened ProjectDataTypeArchive
	 * @throws VersionException  if the archive is not the current version, and either it can't be
	 * upgraded or it was told not to upgrade.
	 * @throws CancelledException if the operation was cancelled
	 * @throws IOException if an general I/O exception occurs while reading the data from the
	 * database file.
	 * @throws DuplicateIdException if the archive has the same id as an already open archive (that
	 * is not from the same DomainFile - this is an unexpected situation) 
	 */
	public ProjectDataTypeArchive openProjectArchive(DomainFile file, int version,
			Upgrade upgradeStrategy, Recover recoverStrategy, boolean rememberInTool,
			TaskMonitor monitor)
			throws VersionException, CancelledException, IOException, DuplicateIdException {

		ProjectDataTypeArchive archive = openStores.getArchiveForDomainFile(file, version);
		if (archive != null) {
			return archive;
		}
		// The task has the open logic, so create a task and call its openArchive method directly.
		OpenProjectArchiveTask task = new OpenProjectArchiveTask(file, version,
			upgradeStrategy, recoverStrategy, this);
		archive = task.openArchive(monitor);
		checkForDuplicateArchiveID(archive);
		openStores.addArchive(archive, rememberInTool);
		archive.release(this);
		return archive;
	}

	/**
	 * Opens the give DomainFile in the tool as a ProjectDataTypeArchive in a background thread. 
	 * This method should be used by clients that are working in the swing thread.
	 * @param file the DomainFile to open
	 * @param version the version (if the file is versioned, otherwise use DomainFile.DEFAULT_VERSION)
	 * @param upgradeStrategy determine what happens if the archive needs to be upgraded before
	 * opening. The options are to do the upgrade, don't do the upgrade, or ask which pops up a 
	 * dialog asking if it is ok to upgrade.
	 * @param recoverStrategy determine what happens if the archive has crash recovery data. The
	 * options are to recover the crash data changes, not recover the changes, or to ask which
	 * popups a dialog asking if the crash recovery data should be used.
	 * @param rememberInTool specifies if this archive should be remembered to be opened the next
	 * time the tool is launched.
	 * @return the newly opened ProjectArchive or null if the open failed. (Exceptions are caught
	 * and reported in the task)
	 */
	public ProjectDataTypeArchive openProjectArchiveInTask(DomainFile file, int version,
			Upgrade upgradeStrategy, Recover recoverStrategy, boolean rememberInTool) {
		ProjectDataTypeArchive archive = openStores.getArchiveForDomainFile(file, version);
		if (archive != null) {
			return archive;
		}
		OpenProjectArchiveTask task =
			new OpenProjectArchiveTask(file, version, upgradeStrategy, recoverStrategy, this);
		TaskLauncher.launch(task);
		archive = task.getArchive();
		if (archive == null) {
			return null;
		}
		try {
			checkForDuplicateArchiveID(archive);
		}
		catch (DuplicateIdException e) {
			Msg.showError(this, null, "Error Opening Project Archive", e.getMessage());
			return null;
		}
		openStores.addArchive(archive, rememberInTool);
		archive.release(this);
		return archive;
	}

	/**
	 * Creates a new FileDataType archive given a non-existing file
	 * @param file the file to use for the new archive (the file must not currently exist)
	 * @return the newly create FileDataTypeArchive or null if the create failed
	 */
	public FileDataTypeArchive createFileArchive(File file) {
		try {
			FileDataTypeArchive archive = DataTypeArchiveFactory.createFileArchive(file, this);
			addArchivePath(new ResourceFile(file));
			openStores.addArchive(archive, true);
			archive.release(this);
			return archive;
		}
		catch (Exception e) {
			Msg.showError(this, plugin.getProvider().getComponent(), "Create Archive Failed",
				"Error creating archive file (" + file.getName() + "): " + e.getMessage());
		}
		return null;
	}

	/**
	 * Opens the give {@link ResourceFile} in the tool as a FileDataTypeArchive. This method should 
	 * be used by clients that are already in the background and have a TaskMonitor that can be
	 * used to cancel the operation.
	 * @param file the {@link ResourceFile} to open
	 * @param openForUpdate specifies if the file should be open for update or read-only. Note that
	 * if openForUpdate is true and the ResourceFile does not represent a modifiable file, an 
	 * {@link IOException} will be thrown.
	 * @param upgradeStrategy determine what happens if the archive needs to be upgraded before
	 * opening. The options are to do the upgrade, don't do the upgrade, or ask which pops up a 
	 * dialog asking if it is ok to upgrade.
	 * @param rememberInTool specifies if this archive should be remembered to be opened the next
	 * time the tool is launched.
	 * @param monitor The task monitor that can be used to cancel the operation
	 * @return new newly opened ProjectDataTypeArchive
	 * @throws VersionException  if the archive is not the current version, and either it can't be
	 * upgraded or it was told not to upgrade.
	 * @throws CancelledException if the operation was cancelled
	 * @throws IOException if an general I/O exception occurs while reading the data from the
	 * database file.
	 * @throws DuplicateIdException if the archive has the same id as an already open archive (that
	 * is not from the same DomainFile - this is an unexpected situation) 
	 */
	public FileDataTypeArchive openFileArchive(ResourceFile file, boolean openForUpdate,
			Upgrade upgradeStrategy, boolean rememberInTool, TaskMonitor monitor)
			throws VersionException, IOException, DuplicateIdException, CancelledException {
		FileDataTypeArchive archive = openStores.getArchiveForFile(file);
		if (archive != null) {
			if (openForUpdate && !archive.isChangeable()) {
				// if the file is open read-only and we want it open for update, close the existing
				openStores.removeArchive(archive);
			}
			else {
				return archive;
			}
		}
		OpenFileArchiveTask task =
			new OpenFileArchiveTask(file, openForUpdate, upgradeStrategy, this);

		archive = task.openArchive(monitor);
		if (archive != null) {
			checkForDuplicateArchiveID(archive);
			openStores.addArchive(archive, rememberInTool);
			archive.release(this);
		}
		return archive;
	}

	/**
	 * Opens the give {@link ResourceFile} in the tool as a FileDataTypeArchive in background
	 * thread. This method should be used by clients on the swing thread
	 * @param file the {@link ResourceFile} to open
	 * @param openForUpdate specifies if the file should be open for update or read-only. Note that
	 * if openForUpdate is true and the ResourceFile does not represent a modifiable file, an 
	 * {@link IOException} will be thrown.
	 * @param upgradeStrategy determine what happens if the archive needs to be upgraded before
	 * opening. The options are to do the upgrade, don't do the upgrade, or ask which pops up a 
	 * dialog asking if it is ok to upgrade.
	 * @param rememberInTool specifies if this archive should be remembered to be opened the next
	 * time the tool is launched.
	 * @return new newly opened FileDataTypeArchive or null if an error occurred. The error will
	 * be reported by the task
	 */
	public FileDataTypeArchive openFileArchiveInTask(ResourceFile file, boolean openForUpdate,
			Upgrade upgradeStrategy, boolean rememberInTool) {
		FileDataTypeArchive archive = openStores.getArchiveForFile(file);
		if (archive != null) {
			if (openForUpdate && !archive.isChangeable()) {
				// if the file is open read-only and we want it open for update, close the existing
				openStores.removeArchive(archive);
			}
			else {
				return archive;
			}
		}
		OpenFileArchiveTask task =
			new OpenFileArchiveTask(file, openForUpdate, upgradeStrategy, this);
		TaskLauncher.launch(task);
		archive = task.getArchive();
		if (archive == null) {
			return null;
		}
		try {
			checkForDuplicateArchiveID(archive);
		}
		catch (DuplicateIdException e) {
			Msg.showError(this, null, "Error Opening Project Archive", e.getMessage());
			return null;
		}
		openStores.addArchive(archive, rememberInTool);
		archive.release(this);
		return archive;

	}

	/**
	 * Updates the current program. May be null if the current program is closed or deactivated.
	 * @param program the currently active program or null if the program is closed or about to
	 * be swapped out for another
	 */
	public void setProgram(Program program) {
		openStores.setProgram(program);
		if (program != null) {
			DataTypeManager programDataTypeManager = program.getDataTypeManager();
			List<SourceArchive> sources = programDataTypeManager.getSourceArchives();
			for (SourceArchive source : sources) {
				if (openStores.isAlreadyOpen(source)) {
					continue;
				}
				ArchiveType archiveType = source.getArchiveType();
				if (archiveType == ArchiveType.PROJECT) {
					findAndOpenProjectArchiveForSource(source);
				}
				else if (archiveType == ArchiveType.FILE) {
					findAndOpenFileArchiveForSource(source);
				}
			}
		}
	}

	/**
	 * Saves the given archive.
	 * @param archive the DataTypeArchive to save
	 */
	public void save(PersistentDataTypeArchive archive) {
		if (!archive.isChanged()) {
			return;
		}
		PluginTool tool = plugin.getTool();
		tool.prepareToSave(archive);
		DataTypeArchiveSaveTask task = new DataTypeArchiveSaveTask(archive, tool);
		TaskLauncher.launch(task);
		openStores.notifyStateChanged(archive);
	}

	/**
	 * Removes the SourceArchive corresponding to the invalid archive from the active program
	 * and removes the association from  all datatypes with that SourceArchive.
	 * @param archive the InvalidArchive to remove the SourceArchive that it represents
	 */
	public void removeInvalidArchiveFromProgram(InvalidArchive archive) {
		closeInvalidArchive(archive);
		Program program = openStores.getProgram();
		if (program == null) {
			return;
		}

		DataTypeManager programDataTypeManager = program.getDataTypeManager();
		program.withTransaction("Remove Invalid Source Archive From Program", () -> {
			UniversalID sourceArchiveID = archive.id();
			SourceArchive sourceArchive = programDataTypeManager.getSourceArchive(sourceArchiveID);
			if (sourceArchive != null) {
				programDataTypeManager.removeSourceArchive(sourceArchive);
			}
		});
	}

	/**
	 * Initiates a save as operation. The user will be prompted for additional information needed
	 * @param archive the archive to do a save as operation on
	 */
	public void saveAs(PersistentDataTypeArchive archive) {
		if (!plugin.canCloseDomainObject(archive)) {
			return;
		}
		if (archive instanceof FileDataTypeArchive fileArchive) {
			saveFileArchiveAs(fileArchive);
		}
		else if (archive instanceof ProjectDataTypeArchive projectArchive) {
			PluginTool tool = plugin.getTool();
			ProjectArchiveSaveAsDialog dialog =
				new ProjectArchiveSaveAsDialog(tool, projectArchive);
			tool.showDialog(dialog);
		}
		openStores.notifyStateChanged(archive);
	}

	/**
	 * Closes all open DataTypeArchives.
	 */
	public void closeAllArchives() {
		List<PersistentDataTypeArchive> archives = openStores.getArchives();
		for (PersistentDataTypeArchive archive : archives) {
			openStores.removeArchive(archive);
		}
	}

//==================================================================================================
// Pass through methods
//==================================================================================================
	/**
	 * {@return the modification count for the last time any archive had changes}
	 */
	public long getModificationCount() {
		return openStores.getModificationCount();
	}

	/**
	 * {@return the current active program. May be null}
	 */
	public Program getProgram() {
		return openStores.getProgram();
	}

	/**
	 * @return all the current DataTypeManagers in the tool. This includes the built-in 
	 * DataTypeManager, the currently active program's DataTypeManager, and all DataTypeArchive's
	 * DataTypeManagers}
	 */
	public DataTypeManager[] getDataTypeManagers() {
		return openStores.getDataTypeManagers();
	}

	/**
	 * Closes the archive from the tool. (May not actually close the archive if some other client
	 * has a consumer registered on the archive.)
	 * @param archive the archive to close with respect to the tool
	 */
	public void closeArchive(PersistentDataTypeArchive archive) {
		openStores.removeArchive(archive);
	}

	/**
	 * {@return a list of all open file or project datatype archives}
	 */
	public List<PersistentDataTypeArchive> getOpenArchives() {
		return openStores.getArchives();
	}

	/**
	 * {@return a list of all favorite datatypes from all current DataTypeManagers open in the tool}
	 */
	public List<DataType> getFavoriteDataTypes() {
		return openStores.getFavoriteDataTypes();
	}

	/**
	 * {@return a list of all datatypes from all current DataTypeManagers open in the tool}
	 */
	public List<DataType> getSortedDataTypeList() {
		return openStores.getSortedDataTypeList();
	}

	/**
	 * {@return a list of all current categories in all current DataTypeManagers open in the tool}
	 */
	public List<CategoryPath> getSortedCategoryPathList() {
		return openStores.getSortedCategoryPathList();
	}

	/**
	 * Adds a DataTypeManagerChangeListener to all open DataTypeManagers open in the tool}
	 * @param listener the listener to be notified of datatype changes
	 */
	public void addDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		openStores.addDataTypeManagerChangeListener(listener);
	}

	/**
	 * Removes a DataTypeManagerChangeListener from all open DataTypeManagers open in the tool}
	 * @param listener the listener to be removed
	 */
	public void removeDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		openStores.removeDataTypeManagerChangeListener(listener);
	}

	/**
	 * {@return a list of all open FileDataTypeArhives}
	 */
	public List<FileDataTypeArchive> getOpenFileArchives() {
		return openStores.getOpenFileArchives();
	}

	/**
	 * {@return a list of all open ProjetDataTypeArhives}
	 */
	public List<ProjectDataTypeArchive> getProjectArchives() {
		return openStores.getOpenProjectArchives();
	}

	/**
	 * {@return the DatatypeManager associated with the given SourceArchive}
	 * @param source the SourceArchive to find its associated DataTypeManager
	 */
	public DataTypeManager getDataTypeManager(SourceArchive source) {
		return openStores.getDataTypeManager(source);
	}

	/**
	 * Removes the given InvalidArchive from the tool
	 * @param archive the invalid archive to remove from the tool
	 */
	public void closeInvalidArchive(InvalidArchive archive) {
		openStores.removeInvalidArchive(archive);
	}

	/**
	 * Adds an ArchiveManagerListener to all open DataTypeManagers open in the tool}
	 * @param listener the listener to be notified of archive changes
	 */
	public void addArchiveManagerListener(ArchiveManagerListener listener) {
		openStores.addArchiveManagerListener(listener);
	}

	/**
	 * removes an ArchiveManagerListener from all open DataTypeManagers open in the tool}
	 * @param listener the listener to be removed
	 */
	public void removeArchiveManagerListener(ArchiveManagerListener listener) {
		openStores.removeArchiveManagerListener(listener);
	}

	public List<InvalidArchive> getInvalidArchives() {
		return openStores.getInvalidArchives();
	}

//==================================================================================================
// Private methods
//==================================================================================================
	private void saveFileArchiveAs(FileDataTypeArchive archive) {
		ArchiveFileChooser fileChooser = new ArchiveFileChooser(null);
		File file = fileChooser.promptUserForFile(archive.getName());
		fileChooser.dispose();
		if (file == null) {
			return;
		}
		if (file.exists()) {
			Msg.showInfo(this, null, "Cannot Perform Save As",
				"Cannot save archive to " + file.getName() + "\nbecause " +
					file.getName() + " already exists.");
			return;
		}
		TaskLauncher.launchModal("Save As", monitor -> {
			try {
				archive.saveAs(file, monitor);
			}
			catch (CancelledException e) {
				// Use chose this, nothing to report
			}
			catch (DuplicateFileException de) {
				Msg.showError(this, null, "Unable to Save File",
					"Archive already exists: " + file.getName());
			}
			catch (IOException ioe) {
				Msg.showError(this, null, "Unable to Save File",
					"Unexpected exception attempting to save archive: " + file.getName(), ioe);
			}
		});

	}

	private void findAndOpenProjectArchiveForSource(SourceArchive source) {
		String domainFileID = source.getDomainFileID();
		ProjectData projectData = plugin.getTool().getProject().getProjectData();
		DomainFile domainFile = projectData.getFileByID(domainFileID);
		if (domainFile == null) {
			openStores.createInvalidArchive(source);
		}
		else {
			openProjectArchiveInTask(domainFile, DomainFile.DEFAULT_VERSION, Upgrade.ASK,
				Recover.ASK, true);
		}
	}

	private void findAndOpenFileArchiveForSource(SourceArchive sourceArchive) {
		String name = sourceArchive.getName();
		UniversalID id = sourceArchive.getSourceArchiveID();
		if (findAndOpenFileArchive(name, id) == null) {
			openStores.createInvalidArchive(sourceArchive);
		}
	}

	private FileDataTypeArchive findAndOpenFileArchive(String archiveName, UniversalID archiveID) {

		if (archiveName.endsWith(FileDataTypeArchive.SUFFIX)) {
			archiveName = archiveName.substring(0,
				archiveName.length() - FileDataTypeArchive.SUFFIX.length());
		}

		String archiveFileName = archiveName + FileDataTypeArchive.SUFFIX;

		Path[] pathsFromPreferences = getArchivePaths();
		for (Path path : pathsFromPreferences) {
			if (!path.isEnabled() || !isAllowedArchivePath(path.getPathAsString())) {
				continue;
			}
			ResourceFile file = new ResourceFile(path.getPath(), archiveFileName);
			if (file.exists()) {
				FileDataTypeArchive archive =
					openFileArchiveInTask(file, false, Upgrade.ASK, false);
				if (matchesId(archive, archiveID)) {
					return archive;
				}
				openStores.removeArchive(archive);
				return null;
			}
		}

		// Look for archive provided with installation (read-only)
		ResourceFile file = DataTypeArchiveUtility.findArchiveFile(archiveFileName);
		if (file == null) {
			Msg.showError(this, plugin.getProvider().getComponent(), "Open Archive Failed",
				"Archive file not found: " + archiveFileName + FileDataTypeArchive.SUFFIX);
			return null;
		}
		return openFileArchiveInTask(file, false, Upgrade.ASK, false);
	}

	private boolean matchesId(FileDataTypeArchive archive, UniversalID archiveID) {
		return archive != null && archive.getUniversalID().equals(archiveID);
	}

	/**
	 * Determine if archive path is allowed.
	 * An attempt is made to disallow any path which appears to be contained
	 * within a Ghidra installation.
	 * @param path directory or file archive path
	 * @return true if path is allowed
	 */
	private boolean isAllowedArchivePath(String path) {

		if (path.startsWith(Path.GHIDRA_HOME)) {
			return false; // Ghidra type info directories will always be searched
		}

		for (String unallowed : UNALLOWED_ARCHIVE_PATH_FRAGMENTS) {
			if (path.indexOf(unallowed) > 0) {
				// Remembering paths to older Ghidra installations is bad
				return false;
			}
		}

		return true;
	}

	private void checkForDuplicateArchiveID(PersistentDataTypeArchive archive) throws DuplicateIdException {
		UniversalID id = archive.getDataTypeManager().getUniversalID();
		DataTypeManager existing = openStores.getDataTypeManager(id);
		if (existing != null) {
			archive.release(this);
			throw new DuplicateIdException(archive.getName(), existing.getName());
		}
	}

	private ProjectDataTypeArchive doReopenProjectArchive(ProjectDataTypeArchive archive) {
		// When re-opened the latest version will be opened
		GTreeState treeState = getTreeState();
		DomainFile domainFile = archive.getDomainFile();
		ProjectLocator projectLocator = domainFile.getProjectLocator();
		String path = domainFile.getPathname();
		boolean isRemembered = openStores.isRemembered(archive);
		openStores.removeArchive(archive);
		ProjectData projectData = AppInfo.getActiveProject().getProjectData(projectLocator);
		DomainFile file = projectData.getFile(path);
		archive = openProjectArchiveInTask(file, DomainFile.DEFAULT_VERSION, Upgrade.ASK,
			Recover.ASK, isRemembered);
		restoreTreeState(treeState);
		return archive;
	}

	private GTreeState getTreeState() {
		GTree tree = plugin.getProvider().getGTree();
		return tree.getTreeState();
	}

	private void restoreTreeState(GTreeState state) {
		GTree tree = plugin.getProvider().getGTree();
		tree.restoreTreeState(state);
	}

	private void initializeFavorites() {
		BuiltInDataTypeManager dtm = BuiltInDataTypeManager.getDataTypeManager();
		dtm.setFavorite(dtm.resolve(PointerDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(CharDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(StringDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(TerminatedStringDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(TerminatedUnicodeDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(FloatDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(DoubleDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(LongDoubleDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(IntegerDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(LongDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(UnsignedIntegerDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(UnsignedLongDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(ByteDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(WordDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(DWordDataType.dataType, null), true);
		dtm.setFavorite(dtm.resolve(QWordDataType.dataType, null), true);
	}

	/**
	 * @return all archive search paths (both enabled and disabled are included)
	 */
	private Path[] getArchivePaths() {
		return PathManager.getPathsFromPreferences(DATA_TYPE_ARCHIVE_PATH_KEY, null,
			DISABLED_DATA_TYPE_ARCHIVE_PATH_KEY);
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

//==================================================================================================
// Inner Classes
//==================================================================================================
	private class MyFolderListener extends DomainFolderListenerAdapter {

		@Override
		public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
			if (!DataTypeArchiveContentHandler.DATA_TYPE_ARCHIVE_CONTENT_TYPE
					.equals(file.getContentType())) {
				return;
			}

			ProjectDataTypeArchive existing =
				openStores.getArchiveForDomainFile(file, DomainFile.DEFAULT_VERSION);
			if (existing == null) {
				return;
			}
			// we only have to worry about the projectArchive being checked out (going from 
			// not changeable to changeable). The other direction (check-in) is not allowed
			// while the archive is open, so if it happens, we won't have the archive in our list.
			if (file.isCheckedOut() && !existing.isChangeable()) {
				reopenArchive(existing);
			}
		}

		@Override
		public void domainFileRemoved(DomainFolder parentFolder, String name, String fileID) {
			// ignore
		}

		@Override
		public void domainFileRenamed(DomainFile file, String oldName) {
			if (!DataTypeArchiveContentHandler.DATA_TYPE_ARCHIVE_CONTENT_TYPE
					.equals(file.getContentType())) {
				return;
			}
			String newName = file.getName();
			String fileId = file.getFileID();
			openStores.archiveNameChanged(fileId, newName);
		}
	}

}

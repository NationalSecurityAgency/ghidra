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

import java.awt.Component;
import java.awt.datatransfer.Clipboard;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import javax.swing.SwingUtilities;
import javax.swing.tree.TreePath;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.Tool;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.actions.PopupActionProvider;
import docking.widgets.OptionDialog;
import docking.widgets.tree.*;
import generic.jar.ResourceFile;
import generic.util.Path;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.datamgr.actions.RecentlyOpenedArchiveAction;
import ghidra.app.plugin.core.datamgr.actions.associate.*;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.plugin.core.datamgr.archive.InvalidArchive;
import ghidra.app.plugin.core.datamgr.editor.DataTypeEditorManager;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.plugin.core.datamgr.util.*;
import ghidra.app.services.*;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.Application;
import ghidra.framework.data.DomainFileProxy;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.store.FileSystem;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.*;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.datastruct.LRUMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Plugin to pop up the dialog to manage data types in the program
 * and archived data type files. The dialog shows a single tree with
 * different categories.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Window for managing datatypes",
	description = "Provides the window for managing and categorizing dataTypes.  " +
			"The datatype display shows all built-in datatypes, datatypes in the " +
			"current program, and datatypes in all open archives.",
	servicesProvided = { DataTypeManagerService.class, DataTypeQueryService.class, DataTypeArchiveService.class }
)
//@formatter:on
public class DataTypeManagerPlugin extends ProgramPlugin
		implements DomainObjectListener, DataTypeManagerService, PopupActionProvider {

	private static final String SEARCH_PROVIDER_NAME = "Search DataTypes Provider";
	private static final int RECENTLY_USED_CACHE_SIZE = 10;

	private static final String STANDARD_ARCHIVE_MENU = "Standard Archive";
	private static final String RECENTLY_OPENED_MENU = "Recently Opened Archive";
	private final static String ARCHIVE_NAMES = "ArchiveNames";
	private static final String PROJECT_NAME_DELIMETER = ":";
	private final static String RECENT_NAMES = "RecentArchiveNames";
	private static final String FAVORITES = "Favorite Dts";
	private static final String RELATIVE_PATH_PREFIX = ".";

	private ArchiveManager archiveManager;
	private DataTypesProvider provider;
	private DataTypesTableProvider tableProvider;
	private List<DataTypesTableProvider> disconnectedTableProviders = new ArrayList<>();

	private Map<String, DockingAction> recentlyOpenedArchiveMap;
	private Map<String, DockingAction> installArchiveMap;
	private Clipboard clipboard = new Clipboard(getName());
	private DataTypeEditorManager editorManager;
	private DataTypePropertyManager dataTypePropertyManager;
	private RecentlyUsedDataType recentlyUsedDataType = new RecentlyUsedDataType();

	public DataTypeManagerPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		recentlyOpenedArchiveMap = new LRUMap<>(RECENTLY_USED_CACHE_SIZE) {
			@Override
			protected void eldestEntryRemoved(Entry<String, DockingAction> eldest) {
				DockingAction action = eldest.getValue();
				if (action == null) {
					return; // this implies we have an entry that no longer exists in the project
				}
				removeRecentAction(action);
			}
		};

		archiveManager = new ArchiveManager(this);
		dataTypePropertyManager = new DataTypePropertyManager();
		provider = new DataTypesProvider(this, "DataTypes Provider");
		tableProvider = new DataTypesTableProvider(this);
		createActions();

		archiveManager.addArchiveManagerListener(new ArchiveManagerListener() {
			@Override
			public void archiveClosed(PersistentDataTypeArchive archive) {
				editorManager.dismissEditors(archive.getDataTypeManager());
				tool.setConfigChanged(true);
				if (archive instanceof ProjectDataTypeArchive projectArchive) {
					projectArchive.removeListener(DataTypeManagerPlugin.this);
				}
				provider.archiveClosed(archive);
			}

			@Override
			public void archiveOpened(PersistentDataTypeArchive archive) {
				tool.setConfigChanged(true);
				if (archive instanceof FileDataTypeArchive fileArchive) {
					addRecentlyOpenedArchiveFile(fileArchive.getFile());
				}
				else if (archive instanceof ProjectDataTypeArchive projectArchive) {
					projectArchive.addListener(DataTypeManagerPlugin.this);
					addRecentlyOpenedProjectArchive(projectArchive);
				}
			}

			@Override
			public void programOpened(Program program) {
				// don't care
			}

			@Override
			public void programClosed(Program program) {
				// don't care
			}

			@Override
			public void invalidArchiveAdded(InvalidArchive invalidArchive) {
				// don't care
			}

			@Override
			public void invalidArchiveRemoved(InvalidArchive invalidArchive) {
				// don't care
			}

			@Override
			public void stateChanged(DataTypeStore store) {
				provider.archiveChanged(store.getName());
			}

		});

		editorManager = new DataTypeEditorManager(this);

		tool.addPopupActionProvider(this);
		tool.setMenuGroup(new String[] { SyncRefreshAction.MENU_NAME }, "SYNC");
		tool.setMenuGroup(new String[] { UpdateAction.MENU_NAME }, "SYNC");
		tool.setMenuGroup(new String[] { CommitAction.MENU_NAME }, "SYNC");
		tool.setMenuGroup(new String[] { RevertAction.MENU_NAME }, "SYNC");
		tool.setMenuGroup(new String[] { DisassociateAction.MENU_NAME }, "SYNC");
		tool.setMenuGroup(new String[] { RECENTLY_OPENED_MENU }, "Recent");
		tool.setMenuGroup(new String[] { STANDARD_ARCHIVE_MENU }, "Recent");
	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (CodeViewerService.class.isAssignableFrom(interfaceClass)) {
			CodeViewerService codeViewerService = (CodeViewerService) service;
			codeViewerService.addProgramDropProvider(new DataDropOnBrowserHandler(this));
		}
	}

	public void addRecentlyOpenedArchiveFile(ResourceFile file) {
		if (file == null) {
			return; // this can happen with a new archive that hasn't been saved yet
		}
		Path path = new Path(file);
		String absoluteFilePath = path.getPathAsString();
		if (!absoluteFilePath.endsWith(FileDataTypeArchive.SUFFIX)) {
			// ignore invalid archive files
			return;
		}

		// checking for the value maintains access-order of the archive
		if (recentlyOpenedArchiveMap.get(absoluteFilePath) == null) {

			RecentlyOpenedArchiveAction action =
				new RecentlyOpenedArchiveAction(this, absoluteFilePath, RECENTLY_OPENED_MENU);
			action.setHelpLocation(new HelpLocation(getName(), "Recent_Archives"));
			recentlyOpenedArchiveMap.put(absoluteFilePath, action);
		}
		updateRecentlyOpenedArchivesMenu();
	}

	/**
	 * Add project archive name to recently opened list
	 * @param projectName the project name
	 * @param pathname the pathname
	 */
	public void addRecentlyOpenedProjectArchive(String projectName, String pathname) {
		String projectPathname = getProjectPathname(projectName, pathname);
		if (recentlyOpenedArchiveMap.get(projectPathname) != null) {
			return;
		}

		RecentlyOpenedArchiveAction action = null;
		if (getProjectArchiveFile(projectName, pathname) != null) {
			action = new RecentlyOpenedArchiveAction(this, projectPathname, RECENTLY_OPENED_MENU);
			action.setHelpLocation(new HelpLocation(getName(), "Recent_Archives"));
		}

		recentlyOpenedArchiveMap.put(projectPathname, action);
		updateRecentlyOpenedArchivesMenu();
	}

	/**
	 * Add project archive to recently opened list provided it is contained within the
	 * active project and is not a specific version (i.e., only latest version can be
	 * remembered).
	 * @param pa project archive
	 */
	public void addRecentlyOpenedProjectArchive(ProjectDataTypeArchive pa) {
		String projectPathname = getProjectPathname(pa, true);
		if (projectPathname != null) { // projectPathname will be null if we can't remember it
			DomainFile df = pa.getDomainFile();
			addRecentlyOpenedProjectArchive(df.getProjectLocator().getName(), df.getPathname());
		}
	}

	/**
	 * Get a project archive file by project name and pathname
	 * @param projectName the project name
	 * @param pathname the project pathname
	 * @return project archive domain file or null if it does not exist
	 * or can not be found (e.g., projectName is not the active project)
	 */
	public DomainFile getProjectArchiveFile(String projectName, String pathname) {
		Project project = tool.getProjectManager().getActiveProject();
		if (project != null && project.getName().equals(projectName)) {
			DomainFile df = project.getProjectData().getFile(pathname);
			if (df != null &&
				ProjectDataTypeArchive.class.isAssignableFrom(df.getDomainObjectClass())) {
				return df;
			}
		}
		return null;
	}

	@Override
	public void dispose() {
		tool.removePopupActionProvider(this);
		archiveManager.dispose();
	}

	@Override
	public void readConfigState(SaveState saveState) {
		restoreArchiveNames(saveState);
		restoreRecentlyOpenedArchiveNames(saveState);
		restoreFavorites(saveState);
		provider.restore(saveState);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		saveArchiveNames(saveState);
		saveRecentlyOpenedArchiveNames(saveState);
		saveFavorites(saveState);
		provider.save(saveState);
	}

	private void restoreRecentlyOpenedArchiveNames(SaveState saveState) {
		String[] recentFilenames = saveState.getStrings(RECENT_NAMES, null);
		List<String> archivePaths = resolveArchivePaths(recentFilenames);
		for (String path : archivePaths) {
			if (path.startsWith(PROJECT_NAME_DELIMETER)) {
				String[] projectPathname = parseProjectPathname(path);
				if (projectPathname != null) {
					addRecentlyOpenedProjectArchive(projectPathname[0], projectPathname[1]);
				}
			}
			else {
				ResourceFile file = new ResourceFile(path);
				if (file.exists()) {
					file = file.getCanonicalFile();
					addRecentlyOpenedArchiveFile(file);
				}
			}
		}
	}

	private void restoreFavorites(SaveState saveState) {
		String[] names = saveState.getStrings(FAVORITES, new String[0]);
		if (names.length == 0) {
			return;
		}
		BuiltInDataTypeManager builtinDtm = BuiltInDataTypeManager.getDataTypeManager();
		Set<DataType> favorites = new HashSet<>();
		for (String dtName : names) {
			DataType dataType = builtinDtm.getDataType(dtName);
			if (dataType != null) {
				favorites.add(dataType);
			}
		}

		List<DataType> currentFavoritesList = builtinDtm.getFavorites();
		for (DataType type : currentFavoritesList) {
			if (favorites.contains(type)) {
				favorites.remove(type);
			}
			else {
				builtinDtm.setFavorite(type, false);
			}
		}
		for (DataType dataType : favorites) {
			builtinDtm.setFavorite(dataType, true);
		}
	}

	private void restoreArchiveNames(SaveState saveState) {
		String[] savedFilenames = saveState.getStrings(ARCHIVE_NAMES, new String[0]);
		List<String> archivePaths = resolveArchivePaths(savedFilenames);
		openArchives(archivePaths);

	}

	private void openArchives(List<String> archiveFilenames) {
		for (String filename : archiveFilenames) {
			String[] projectPathname = parseProjectPathname(filename);
			if (projectPathname != null) {
				DomainFile df = getProjectArchiveFile(projectPathname[0], projectPathname[1]);
				if (df != null) {
					archiveManager.openProjectArchiveInTask(df, DomainFile.DEFAULT_VERSION,
						Upgrade.ASK, Recover.ASK, true);
				}
			}
			else {
				File file = new File(filename);
				if (!file.exists()) {
					continue; // if the file does not exist, skip it.
				}
				archiveManager.openFileArchiveInTask(new ResourceFile(file), false, Upgrade.ASK,
					true);
			}
		}
	}

	private void saveRecentlyOpenedArchiveNames(SaveState saveState) {
		List<String> recentMenuList = new ArrayList<>();
		for (String file : recentlyOpenedArchiveMap.keySet()) {
			recentMenuList.add(file);
		}
		saveState.putStrings(RECENT_NAMES, getSaveableArchiveNames(recentMenuList));
	}

	private void saveArchiveNames(SaveState saveState) {
		List<String> rememberedArchivePaths = new ArrayList<>();
		Set<PersistentDataTypeArchive> rememberedArchives = archiveManager.getRememberedArchives();
		for (PersistentDataTypeArchive archive : rememberedArchives) {
			String filePath = null;
			if (archive instanceof FileDataTypeArchive fileArchive) {
				ResourceFile file = fileArchive.getFile();
				rememberedArchivePaths.add(file.getAbsolutePath());
			}
			else if (archive instanceof ProjectDataTypeArchive projectArchive) {
				filePath = getProjectPathname(projectArchive, true);
				if (filePath != null) {
					rememberedArchivePaths.add(filePath);
				}
			}
		}
		saveState.putStrings(ARCHIVE_NAMES, getSaveableArchiveNames(rememberedArchivePaths));
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

	void saveFavorites(SaveState saveState) {
		BuiltInDataTypeManager builtInDtm = BuiltInDataTypeManager.getDataTypeManager();
		List<DataType> favoritesList = builtInDtm.getFavorites();
		String[] names = new String[favoritesList.size()];
		for (int i = 0; i < names.length; i++) {
			DataType dataType = favoritesList.get(i);
			names[i] = dataType.getPathName();
		}

		saveState.putStrings(FAVORITES, names);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent event) {
		if (event.contains(DomainObjectEvent.RESTORED)) {
			Object source = event.getSource();
			if (source instanceof PersistentDataTypeArchive archive) {
				provider.domainObjectRestored(archive);
				dataTypePropertyManager.domainObjectRestored(archive);
				// NOTE: each editor that cares about a restored DataTypeManager must establish
				// a DataTypeManagerChangeListener and will be notified via the restored method.
			}
		}
		else if (event.contains(DomainObjectEvent.RENAMED)) {
			provider.programRenamed();
		}
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
		archiveManager.setProgram(null);
		dataTypePropertyManager.programClosed(program);
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
		provider.programActivated(program);
		archiveManager.setProgram(program);
		tableProvider.programActivated(program);

		dataTypePropertyManager.programOpened(program);
	}

	@Override
	protected void programClosed(Program program) {
		// assumption: at this point programDeactivated(Program) has been called, so we don't
		// have to perform any cleanup that is done by that method.
		provider.programClosed(program);
		editorManager.dismissEditors(program.getDataTypeManager());

		List<DataTypesTableProvider> snapshots = new LinkedList<>(disconnectedTableProviders);
		for (DataTypesTableProvider snapshot : snapshots) {
			if (program.equals(snapshot.getProgram())) {
				snapshot.closeComponent();
			}
		}
	}

	@Override
	protected boolean canCloseDomainObject(DomainObject dObj) {
		if (dObj instanceof PersistentDataTypeArchive archive) {
			return editorManager.checkEditors(archive.getDataTypeManager(), true);
		}
		else if (dObj instanceof Program program) {
			return editorManager.checkEditors(program.getDataTypeManager(), true);
		}
		return true;
	}

	@Override
	protected boolean canClose() {
		if (!editorManager.checkEditors(null, true)) {
			return false;
		}
		editorManager.dismissEditors(null);
		List<FileDataTypeArchive> archives = archiveManager.getOpenFileArchives();
		for (FileDataTypeArchive archive : archives) {
			if (!resolveModifiedArchive(archive)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Prompts the user to save any changes to the given archive in preparation for closing.
	 * @param archive the archive that is to be prompted to save
	 * @return true if the archive can be closed (The user either saved it or declined to save it).
	 * Only returns false if the user cancelled the operation.
	 */
	public boolean resolveModifiedArchive(PersistentDataTypeArchive archive) {

		if (!archive.isChanged()) {
			return true;
		}

		int result =
			OptionDialog.showYesNoCancelDialog(null, "Save Archive?", "Datatype Archive \"" +
				archive.getName() + "\" has been changed.\n Do you want to save the changes?");

		if (result == OptionDialog.YES_OPTION) {
			archiveManager.save(archive);
		}

		return result != OptionDialog.CANCEL_OPTION;
	}

	@Override
	protected void close() {
		provider.dispose();
	}

	public ArchiveManager getArchiveManager() {
		return archiveManager;
	}

	public DataTypeEditorManager getEditorManager() {
		return editorManager;
	}

	public DataTypesProvider getProvider() {
		return provider;
	}

	DataTypesTableProvider getTableProvider() {
		return tableProvider;
	}

	public Clipboard getClipboard() {
		return clipboard;
	}

	public DataTypesProvider createProvider() {

		DataTypesProvider newProvider = new DataTypesProvider(this, SEARCH_PROVIDER_NAME, true);
		newProvider.setIncludeDataTypeMembersInFilter(provider.isIncludeDataMembersInSearch());
		DtFilterState filterState = provider.getFilterState();
		newProvider.setFilterState(filterState.copy());
		return newProvider;
	}

	public Program getProgram() {
		return currentProgram;
	}

	public DataTypeConflictHandler getConflictHandler() {
		return provider.getConflictHandler();
	}

	void setStatus(String message) {
		tool.setStatusInfo(message);
	}

	public static boolean isValidTypeDefBaseType(Component parent, DataType dataType) {
		if (dataType instanceof FactoryDataType) {
			Msg.showError(DataTypeManagerPlugin.class, parent, "TypeDef not allowed",
				"TypeDef not allowed on a Factory data-type: " + dataType.getName());
			return false;
		}
		if (dataType instanceof Dynamic) {
			Msg.showError(DataTypeManagerPlugin.class, parent, "TypeDef not allowed",
				"TypeDef not allowed on a Dynamic data-type: " + dataType.getName());
			return false;
		}
		if (dataType.getLength() <= 0) {
			Msg.showError(DataTypeManagerPlugin.class, parent, "TypeDef not allowed",
				"Data-type has unknown length: " + dataType.getName());
			return false;
		}
		return true;
	}

	// rebuilds the recently opened archive menu
	private void updateRecentlyOpenedArchivesMenu() {
		List<DockingAction> actionList = new ArrayList<>(recentlyOpenedArchiveMap.values());
		for (DockingAction action : actionList) {
			if (action != null) {
				tool.removeLocalAction(provider, action);
			}
		}

		for (DockingAction action : actionList) {
			if (action != null) {
				tool.addLocalAction(provider, action);
			}
		}
	}

	private void createStandardArchivesMenu() {
		installArchiveMap = new TreeMap<>();
		String gdt = FileDataTypeArchive.SUFFIX;
		List<ResourceFile> gdts = Application.findFilesByExtensionInApplication(gdt);
		for (ResourceFile archiveFile : gdts) {
			Path path = new Path(archiveFile);
			String absolutePath = path.getPathAsString();
			if (!absolutePath.contains("/data/typeinfo/")) {
				continue;
			}

			RecentlyOpenedArchiveAction action =
				new RecentlyOpenedArchiveAction(this, absolutePath, STANDARD_ARCHIVE_MENU);
			action.setHelpLocation(new HelpLocation(getName(), "Standard_Archives"));
			installArchiveMap.put(absolutePath, action);
		}
		for (DockingAction action : installArchiveMap.values()) {
			tool.addLocalAction(provider, action);
		}
	}

	/**
	 * Create the actions for the menu on the tool.
	 */
	private void createActions() {
		createStandardArchivesMenu();

		//@formatter:off
		new ActionBuilder("Edit Data Type", getName())
			.keyBinding("Control Shift D")
			.onAction(this::edit)
			.buildAndInstall(tool);
		//@formatter:on
	}

	private void removeRecentAction(DockingAction action) {
		tool.removeLocalAction(provider, action);
	}

	private void edit(ActionContext c) {
		DataType dt = chooseType();
		if (dt != null) {
			edit(dt);
		}
	}

	private DataType chooseType() {

		int noSizeRestriction = -1;
		DataTypeSelectionDialog selectionDialog =
			new DataTypeSelectionDialog(tool, null, noSizeRestriction, AllowedDataTypes.ALL);

		tool.showDialog(selectionDialog);
		return selectionDialog.getUserChosenDataType();
	}

//**********************************************************************************************
//	DataTypeManagerService methods
//**********************************************************************************************

	@Override
	public HelpLocation getEditorHelpLocation(DataType dataType) {
		return editorManager.getEditorHelpLocation(dataType);
	}

	@Override
	public boolean isEditable(DataType dt) {
		return editorManager.isEditable(dt);
	}

	@Override
	public void edit(DataType dataType) {

		dataType = DataTypeUtils.getBaseDataType(dataType);

		dataType = getEditableDataType(dataType);

		if (dataType != null) {
			getEditorManager().edit(dataType);
		}
	}

	private DataType getEditableDataType(DataType dataType) {

		DataTypeManager dtm = dataType.getDataTypeManager();
		DataTypeStore dataStore = dtm.getDataStore();
		if (dataStore.isChangeable()) {
			return dataType;
		}

		if (isUnmodifiableProjectArchive(dataStore)) {
			return null;
		}

		if (dataStore instanceof FileDataTypeArchive fileArchive) {
			if (!fileArchive.isChangeable()) {
				if (!askToOpenArchiveForUpdate()) {
					return null;
				}

				fileArchive = openForUpdate(fileArchive);

				CategoryPath path = dataType.getCategoryPath();
				String dataTypeName = dataType.getName();
				return updateDataType(path, dataTypeName, fileArchive);
			}
		}

		return null;
	}

	private boolean isUnmodifiableProjectArchive(DataTypeStore dataStore) {
		if (!(dataStore instanceof ProjectDataTypeArchive projectArchive)) {
			return false;
		}

		if (dataStore.isChangeable()) {
			return false;
		}

		DomainFile domainFile = projectArchive.getDomainFile();
		DomainFile originalDomainFile = getOriginalDomainFile(domainFile);
		if (domainFile.getVersion() == originalDomainFile.getLatestVersion() &&
			originalDomainFile.canCheckout()) {
			Msg.showInfo(getClass(), null, "Archive Not Checked Out",
				"You must checkout this archive before you may edit data types.");
		}
		else {
			Msg.showInfo(getClass(), null, "Archive Opened Read-Only",
				"You may not edit data type within a read-only project archive.");
		}
		return true;
	}

	private DomainFile getOriginalDomainFile(DomainFile domainFile) {
		if (domainFile instanceof DomainFileProxy proxy) {
			DomainFile originalDomainFile = proxy.getOriginalDomainFile();
			if (originalDomainFile != null) {
				return originalDomainFile;
			}
		}
		return domainFile;
	}

	private FileDataTypeArchive openForUpdate(FileDataTypeArchive archive) {
		GTree tree = getProvider().getGTree();
		GTreeState state = tree.getTreeState();
		archive = getArchiveManager().reopenFileArchive(archive, true);
		tree.restoreTreeState(state);
		return archive;
	}

	private static DataType updateDataType(CategoryPath path, String dataTypeName,
			PersistentDataTypeArchive archive) {
		if (archive == null) {
			return null;
		}
		DataTypeManager dataTypeManager = archive.getDataTypeManager();
		Category category = dataTypeManager.getCategory(path);
		return category.getDataType(dataTypeName);
	}

	private boolean askToOpenArchiveForUpdate() {
		return (OptionDialog.showYesNoDialog(null, "Open Archive for Edit?",
			"Archive file is not modifiable.\nDo you want to open for edit?") == OptionDialog.OPTION_ONE);
	}

	@Override
	public void edit(Composite composite, String fieldName) {
		editorManager.edit(composite, fieldName);
	}

	@Override
	public DataTypeManager getBuiltInDataTypesManager() {
		return BuiltInDataTypeManager.getDataTypeManager();
	}

	public DataTypeManager getProgramDataTypeManager() {
		DataTypeManager[] managers = getDataTypeManagers();
		for (DataTypeManager manager : managers) {
			if (manager instanceof ProgramDataTypeManager) {
				return manager;
			}
		}
		return null;
	}

	@Override
	public DataType getDataType(String filterText) {
		return promptForDataType(filterText);
	}

	@Override
	public List<DataType> findDataTypes(String dtName, TaskMonitor monitor) {
		List<DataType> results = new ArrayList<>();
		DataTypeManager[] managers = getDataTypeManagers();

		// we put the program's data types at the front of the list so clients can tell if the 
		// types we have found already exist in the program
		DataTypeManager pdtm = getProgramDataTypeManager();
		pdtm.findDataTypes(dtName, results);
		for (DataTypeManager manager : managers) {
			if (!(manager instanceof ProgramDataTypeManager)) {
				manager.findDataTypes(dtName, results);
			}
		}
		return results;
	}

	@Override
	public List<DataType> getDataTypesByPath(DataTypePath path) {
		List<DataType> results = new ArrayList<>();
		DataTypeManager[] managers = getDataTypeManagers();
		for (DataTypeManager manager : managers) {
			DataType dt = manager.getDataType(path);
			if (dt == null) {
				continue;
			}

			if (manager instanceof ProgramDataTypeManager) {
				// we put the program's data type at the front of the list so clients can tell if 
				// the types we have found already exist in the program
				results.add(0, dt);
			}
			else {
				results.add(dt);
			}
		}
		return results;
	}

	@Override
	public DataType getProgramDataTypeByPath(DataTypePath path) {
		DataTypeManager pdtm = getProgramDataTypeManager();
		if (pdtm == null) {
			return null;
		}
		return pdtm.getDataType(path);
	}

	@Override
	public DataType promptForDataType(String filterText) {
		DataTypeChooserDialog dialog = new DataTypeChooserDialog(this);
		if (!StringUtils.isBlank(filterText)) {
			dialog.showPrepopulatedDialog(tool, filterText);
		}
		else {
			tool.showDialog(dialog);
		}

		return dialog.getSelectedDataType();
	}

	@Override
	public DataType getDataType(TreePath selectedPath) {
		DataTypeChooserDialog dialog = new DataTypeChooserDialog(this);
		if (selectedPath != null) {
			dialog.setSelectedPath(selectedPath);
		}
		tool.showDialog(dialog);
		return dialog.getSelectedDataType();
	}

	@Override
	public CategoryPath getCategoryPath(TreePath selectedPath) {
		DataTypeChooserDialog dialog = new DataTypeChooserDialog(this);
		dialog.setCategorySelectionMode(true);
		dialog.setShowProgramArchiveOnly(true);

		if (selectedPath != null) {
			dialog.setSelectedPath(selectedPath);
		}
		tool.showDialog(dialog);
		return dialog.getSelectedCategoryPath();
	}

	@Override
	public DataTypeManager[] getDataTypeManagers() {
		return archiveManager.getDataTypeManagers();
	}

	@Override
	public List<PersistentDataTypeArchive> getDataTypeArchives() {
		return archiveManager.getOpenArchives();
	}

	@Override
	public void closeArchive(DataTypeManager dtm) {
		DataTypeStore dataStore = dtm.getDataStore();
		if (dataStore instanceof PersistentDataTypeArchive archive) {
			archiveManager.closeArchive(archive);
			provider.archiveClosed(archive);
		}
	}

	@Override
	public void closeArchive(PersistentDataTypeArchive archive) {
		archiveManager.closeArchive(archive);
		provider.archiveClosed(archive);
	}

	@Override
	public FileDataTypeArchive openFileArchive(String archiveName, TaskMonitor monitor)
			throws IOException, DuplicateIdException, CancelledException {
		ResourceFile file = DataTypeArchiveUtility.findArchiveFile(archiveName);
		if (file != null) {
			try {
				return openFileArchive(file, false, Upgrade.NO, monitor);
			}
			catch (VersionException e) {
				throw new IOException(e);	// legacy service method doesn't throw VersionException
			}
		}
		return null;
	}

	@Override
	public FileDataTypeArchive openFileArchive(ResourceFile resourceFile, boolean openForUpdate,
			Upgrade upgradeStrategy, TaskMonitor monitor)
			throws IOException, VersionException, DuplicateIdException, CancelledException {

		return archiveManager.openFileArchive(resourceFile, openForUpdate, upgradeStrategy, false,
			monitor);
	}

	@Override
	public ProjectDataTypeArchive openProjectArchive(DomainFile domainFile, Upgrade upgradeStrategy,
			Recover recoverStrategy, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException, DuplicateIdException {
		return archiveManager.openProjectArchive(domainFile, DomainFile.DEFAULT_VERSION,
			upgradeStrategy, recoverStrategy, false, monitor);
	}

	@Override
	public List<DataType> getFavorites() {
		return archiveManager.getFavoriteDataTypes();
	}

	@Override
	public DataType getRecentlyUsed() {
		return recentlyUsedDataType.getDataType();
	}

	@Override
	public List<DataType> getSortedDataTypeList() {
		return archiveManager.getSortedDataTypeList();
	}

	@Override
	public List<CategoryPath> getSortedCategoryPathList() {
		return archiveManager.getSortedCategoryPathList();
	}

	@Override
	public void setDataTypeSelected(DataType dataType) {
		if (provider.isVisible()) {
			// this is a service method, ensure it is on the Swing thread, since it interacts with
			// Swing components
			Swing.runIfSwingOrRunLater(() -> provider.setDataTypeSelected(dataType));
		}
	}

	public void setDataTypeSelected(Collection<DataType> types) {
		provider.clearSelection();
		if (provider.isVisible()) {
			for (DataType dt : types) {
				provider.setDataTypeSelected(dt, true);
			}
		}
	}

	@Override
	public void setCategorySelected(Category category) {
		if (provider.isVisible()) {
			// this is a service method, ensure it is on the Swing thread, since it interacts with
			// Swing components
			Swing.runIfSwingOrRunLater(() -> provider.setCategorySelected(category));
		}
	}

	@Override
	public List<DataType> getSelectedDatatypes() {
		if (provider.isVisible()) {
			return provider.getSelectedDataTypes();
		}
		return Collections.emptyList();
	}

	@Override
	public void setRecentlyUsed(DataType dt) {
		recentlyUsedDataType = new RecentlyUsedDataType(dt);

	}

	@Override
	public void addDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		archiveManager.addDataTypeManagerChangeListener(listener);
	}

	@Override
	public void removeDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		archiveManager.removeDataTypeManagerChangeListener(listener);
	}

	@Override
	public Set<String> getPossibleEquateNames(long value) {
		Set<String> equateNames = new HashSet<>();
		DataTypeManager[] dataTypeManagers = archiveManager.getDataTypeManagers();
		for (DataTypeManager dtm : dataTypeManagers) {
			dtm.findEnumValueNames(value, equateNames);
		}
		return equateNames;
	}

	@Override
	public Class<?>[] getSupportedDataTypes() {
		return new Class[] { ProjectDataTypeArchive.class };
	}

	@Override
	public boolean acceptData(DomainFile[] data) {
		if (data == null || data.length == 0) {
			return false;
		}
		boolean addedArchives = false;

		for (DomainFile df : data) {
			if (df != null &&
				ProjectDataTypeArchive.class.isAssignableFrom(df.getDomainObjectClass())) {
				archiveManager.openProjectArchiveInTask(df, DomainFile.DEFAULT_VERSION, Upgrade.ASK,
					Recover.ASK, true);

				addedArchives = true;
			}
		}

		// if the user drops a file we are opening, the make sure we are brought to attention
		if (addedArchives) {
			showProviderLater();
		}

		return addedArchives;
	}

	private void showProviderLater() {
		SwingUtilities.invokeLater(() -> tool.toFront(provider));
	}

	public boolean commit(DataType dataType) {
		return DataTypeSynchronizer.commit(archiveManager, dataType);
	}

	public boolean update(DataType dataType) {
		return DataTypeSynchronizer.update(archiveManager, dataType);
	}

	public boolean revert(DataType dataType) {
		return DataTypeSynchronizer.update(archiveManager, dataType);
	}

	public void disassociate(DataType dataTypes) {
		DataTypeSynchronizer.disassociate(dataTypes);
	}

	public AddressSetView getCurrentSelection() {
		return currentSelection;
	}

	public DtFilterState getTreeFilterState() {
		return provider.getFilterState();
	}

	void showDataTypesTable() {
		tableProvider.setVisible(true);
	}

	public void addDisconnectedTableProvider(DataTypesTableProvider dataTypesTableProvider) {
		disconnectedTableProviders.add(dataTypesTableProvider);
	}

	public void removeDisconnectedTableProvider(DataTypesTableProvider dataTypesTableProvider) {
		disconnectedTableProviders.remove(dataTypesTableProvider);
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool dockingTool, ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return null;
		}
		DataTypesActionContext dtContext = (DataTypesActionContext) context;
		GTreeNode selectedNode = dtContext.getClickedNode();
		if (!(selectedNode instanceof DataTypeStoreNode archiveNode)) {
			return null;
		}

		List<DockingActionIf> actions = new ArrayList<>();

		DataTypeManager dataTypeManager = archiveNode.getDataTypeManager();
		if (dataTypeManager == null) {
			return null;
		}

		String group = "FGroup"; // after 'Edit'
		List<SourceArchive> sourceArchives = dataTypeManager.getSourceArchives();
		for (SourceArchive sourceArchive : sourceArchives) {
			DataTypeManager sourceDTM = archiveManager.getDataTypeManager(sourceArchive);
			boolean canUpdate = canUpdate(sourceArchive, sourceDTM);
			boolean canCommit = canCommit(sourceArchive, sourceDTM);
			actions.add(new SyncRefreshAction(this, archiveManager, dataTypeManager,
				archiveNode, sourceArchive, true));
			actions.add(new CommitAction(this, archiveManager, dataTypeManager, archiveNode,
				sourceArchive, canCommit));
			actions.add(new UpdateAction(this, archiveManager, dataTypeManager, archiveNode,
				sourceArchive, canUpdate));
			actions.add(new RevertAction(this, archiveManager, dataTypeManager, archiveNode,
				sourceArchive, canCommit));
			actions.add(new DisassociateAction(this, archiveManager, dataTypeManager,
				archiveNode, sourceArchive));
		}

		// the current actions are all pull-right actions--set their group
		for (DockingActionIf action : actions) {
			MenuData popupData = action.getPopupMenuData();
			String pullRightName = popupData.getMenuPath()[0];
			tool.setMenuGroup(new String[] { pullRightName }, group);
		}
		return actions;
	}

	private boolean canUpdate(SourceArchive sourceArchive, DataTypeManager sourceDTM) {
		if (sourceDTM == null) {
			return false;
		}
		long lastChangeTimeForSource = sourceDTM.getLastChangeTimeForMyManager();
		long lastSyncTimeForSource = sourceArchive.getLastSyncTime();
		return lastChangeTimeForSource != lastSyncTimeForSource;
	}

	private boolean canCommit(SourceArchive sourceArchive, DataTypeManager sourceDTM) {
		if (sourceDTM == null) {
			return false;
		}
		return sourceArchive.isDirty();
	}

	@Override
	public DomainFile[] getData() {
		// Program Manager will take care of programs.
		// We need to take care of Project Data Type Archives.
		List<DomainFile> domainFileList = new ArrayList<>();
		List<ProjectDataTypeArchive> allArchives = archiveManager.getProjectArchives();
		for (ProjectDataTypeArchive archive : allArchives) {
			if ((archive instanceof ProjectDataTypeArchive pa) && archive.isChangeable()) {
				domainFileList.add(pa.getDomainFile());
			}
		}
		return domainFileList.toArray(new DomainFile[domainFileList.size()]);
	}

	@Override
	protected boolean saveData() {
		// Note: project archives are saved via this method and file archives are saved via
		// the canClose() method. The reason is to prevent duplicate asks to save an archive. 
		// 
		// There is an inconsistency between these methods getting called depending on whether just
		// a tool is being closed or the front-end is closing. This method is only called in the
		// case when just a tool is closing. When the front-end is closing, this call is skipped
		// and instead a generic dialog for any changed project domain object (which includes 
		// programs and project datatype archives) is called.
		// 
		// So, if we were to try and save file archives here, they wouldn't get saved since this
		// method isn't called when the front-end is closed. 

		List<ProjectDataTypeArchive> archives = archiveManager.getProjectArchives();
		for (ProjectDataTypeArchive archive : archives) {
			if (!resolveModifiedArchive(archive)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Create project archive path string for recently used project archive
	 * @param projectName the project name
	 * @param pathname the pathname used to create the final path
	 * @return recently used project pathname string
	 */
	public static String getProjectPathname(String projectName, String pathname) {
		if (pathname.length() < 2 || !pathname.startsWith(FileSystem.SEPARATOR)) {
			throw new IllegalArgumentException("Absolute project pathname required");
		}
		return PROJECT_NAME_DELIMETER + projectName + PROJECT_NAME_DELIMETER + pathname;
	}

	/**
	 * Determine if we can remember the specified project archive using a simple project path
	 * (e.g., we can't remember specific versions).
	 * @param pa project archive
	 * @param activeProjectOnly if true pa must be contained within the
	 * active project to be remembered.
	 * @return return project path which can be remembered or null
	 */
	public String getProjectPathname(ProjectDataTypeArchive pa, boolean activeProjectOnly) {
		// Project archives are always opened by a user.
		// Only remember it if it is the current version within the current project
		DomainFile df = pa.getDomainFile();
		ProjectLocator projectLocator = df.getProjectLocator();
		String projectName = projectLocator.getName();
		boolean remember = df.isInWritableProject();
		if (!remember) {
			// handle read-only case
			Project project = tool.getProjectManager().getActiveProject();
			remember = (project != null && project.getName().equals(projectName) &&
				df.getVersion() == DomainFile.DEFAULT_VERSION);
		}
		return remember ? getProjectPathname(projectName, df.getPathname()) : null;
	}

	private static List<String> resolveArchivePaths(String[] savedArchivePaths) {
		if (savedArchivePaths == null) {
			return Collections.emptyList();
		}
		List<String> resolvedPaths = new ArrayList<>();
		for (String archivePath : savedArchivePaths) {
			archivePath = adjustArchivePath(archivePath);
			if (archivePath != null) {
				resolvedPaths.add(archivePath);
			}
		}
		return resolvedPaths;
	}

	private static String adjustArchivePath(String pathName) {
		if (pathName.startsWith(PROJECT_NAME_DELIMETER)) {
			return pathName;
		}
		if (pathName.startsWith(RELATIVE_PATH_PREFIX)) {
			ResourceFile file = DataTypeArchiveUtility.findArchiveFile(pathName);
			if (file == null) {
				Msg.error(ArchiveManager.class, "Archive not found: " + pathName);
				return null;
			}
			return file.getAbsolutePath();
		}
		Path path = new Path(pathName);
		return path.getPath().getAbsolutePath();
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

			if (dataTypeManagerName == null && currentProgram != null) {
				DataTypeManager programDataTypeManager = currentProgram.getDataTypeManager();
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
			if (currentProgram != null && currentProgram.getName().equals(dataTypeManagerName)) {
				return currentProgram.getDataTypeManager();
			}
			for (PersistentDataTypeArchive archive : archiveManager.getOpenArchives()) {
				if (archive.getName().equals(dataTypeManagerName)) {
					return archive.getDataTypeManager();
				}
			}
			return BuiltInDataTypeManager.getDataTypeManager();
		}
	}

}

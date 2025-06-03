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
import docking.widgets.tree.GTreeNode;
import generic.jar.ResourceFile;
import generic.util.Path;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.datamgr.actions.RecentlyOpenedArchiveAction;
import ghidra.app.plugin.core.datamgr.actions.UpdateSourceArchiveNamesAction;
import ghidra.app.plugin.core.datamgr.actions.associate.*;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.editor.DataTypeEditorManager;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.DtFilterState;
import ghidra.app.plugin.core.datamgr.util.DataDropOnBrowserHandler;
import ghidra.app.plugin.core.datamgr.util.DataTypeChooserDialog;
import ghidra.app.services.*;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.Application;
import ghidra.framework.main.OpenVersionedFileDialog;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.datastruct.LRUMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskLauncher;
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
	servicesProvided = { DataTypeManagerService.class, DataTypeArchiveService.class }
)
//@formatter:on
public class DataTypeManagerPlugin extends ProgramPlugin
		implements DomainObjectListener, DataTypeManagerService, PopupActionProvider {

	private static final String SEARCH_PROVIDER_NAME = "Search DataTypes Provider";
	private static final int RECENTLY_USED_CACHE_SIZE = 10;

	private static final String STANDARD_ARCHIVE_MENU = "Standard Archive";
	private static final String RECENTLY_OPENED_MENU = "Recently Opened Archive";

	private DataTypeManagerHandler dataTypeManagerHandler;
	private DataTypesProvider provider;

	private Map<String, DockingAction> recentlyOpenedArchiveMap;
	private Map<String, DockingAction> installArchiveMap;
	private Clipboard clipboard = new Clipboard(getName());
	private DataTypeEditorManager editorManager;
	private DataTypePropertyManager dataTypePropertyManager;

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

		dataTypeManagerHandler = new DataTypeManagerHandler(this);
		dataTypePropertyManager = new DataTypePropertyManager();
		provider = new DataTypesProvider(this, "DataTypes Provider");
		createActions();

		dataTypeManagerHandler.addArchiveManagerListener(new ArchiveManagerListener() {
			@Override
			public void archiveClosed(Archive archive) {
				if (archive instanceof ProjectArchive) {
					ProjectArchive projectArchive = (ProjectArchive) archive;
					projectArchive.getDomainObject().removeListener(DataTypeManagerPlugin.this);
				}

				provider.archiveClosed(archive.getDataTypeManager());
			}

			@Override
			public void archiveOpened(Archive archive) {
				if (archive instanceof FileArchive) {
					addRecentlyOpenedArchiveFile(((FileArchive) archive).getFile());
				}
				else if (archive instanceof ProjectArchive) {
					ProjectArchive projectArchive = (ProjectArchive) archive;
					projectArchive.getDomainObject().addListener(DataTypeManagerPlugin.this);
					addRecentlyOpenedProjectArchive((ProjectArchive) archive);
				}
			}

			@Override
			public void archiveDataTypeManagerChanged(Archive archive) {
				provider.archiveChanged(archive);
			}

			@Override
			public void archiveStateChanged(Archive archive) {
				provider.archiveChanged(archive);
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
		if (interfaceClass == CodeViewerService.class) {
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
		if (!absoluteFilePath.endsWith(FileDataTypeManager.SUFFIX)) {
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
		String projectPathname = DataTypeManagerHandler.getProjectPathname(projectName, pathname);
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
	public void addRecentlyOpenedProjectArchive(ProjectArchive pa) {
		String projectPathname = dataTypeManagerHandler.getProjectPathname(pa, true);
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
			if (df != null && DataTypeArchive.class.isAssignableFrom(df.getDomainObjectClass())) {
				return df;
			}
		}
		return null;
	}

	/**
	 * A collection of files that have recently been opened by the user.
	 * @return A collection of files that have recently been opened by the user.
	 */
	public Collection<String> getRecentlyOpenedArchives() {
		return Collections.unmodifiableSet(recentlyOpenedArchiveMap.keySet());
	}

	@Override
	public void dispose() {
		tool.removePopupActionProvider(this);
		dataTypeManagerHandler.closeAllArchives();
		dataTypeManagerHandler.dispose();
	}

	@Override
	public void readConfigState(SaveState saveState) {
		dataTypeManagerHandler.restore(saveState);
		provider.restore(saveState);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		dataTypeManagerHandler.save(saveState);
		provider.save(saveState);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent event) {
		if (event.contains(DomainObjectEvent.RESTORED)) {
			Object source = event.getSource();
			if (source instanceof DataTypeManagerDomainObject) {
				DataTypeManagerDomainObject domainObject = (DataTypeManagerDomainObject) source;
				provider.domainObjectRestored(domainObject);
				dataTypePropertyManager.domainObjectRestored(domainObject);
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
		dataTypeManagerHandler.programClosed();
		dataTypePropertyManager.programClosed(program);
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
		dataTypeManagerHandler.programOpened(program);
		dataTypePropertyManager.programOpened(program);
	}

	@Override
	protected void programClosed(Program program) {
		// assumption: at this point programDeactivated(Program) has been called, so we don't
		// have to perform any cleanup that is done by that method.
		provider.programClosed();
		editorManager.dismissEditors(program.getDataTypeManager());
	}

	@Override
	protected boolean canCloseDomainObject(DomainObject dObj) {
		if (dObj instanceof DataTypeManagerDomainObject) {
			DataTypeManagerDomainObject dtmObject = (DataTypeManagerDomainObject) dObj;
			return editorManager.checkEditors(dtmObject.getDataTypeManager(), true);
		}
		return true;
	}

	@Override
	protected boolean canClose() {
		if (!editorManager.checkEditors(null, true)) {
			return false;
		}
		editorManager.dismissEditors(null);
		dataTypeManagerHandler.updateKnownOpenArchives();
		if (!ArchiveUtils.canClose(dataTypeManagerHandler.getAllModifiedFileArchives(),
			provider.getComponent())) {
			return false;
		}
		return true;
	}

	@Override
	protected void close() {
		provider.dispose();
	}

	public DataTypeManagerHandler getDataTypeManagerHandler() {
		return dataTypeManagerHandler;
	}

	public DataTypeEditorManager getEditorManager() {
		return editorManager;
	}

	public DataTypesProvider getProvider() {
		return provider;
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
		String gdt = FileDataTypeManager.SUFFIX;
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
	public void edit(DataType dt) {
		editorManager.edit(dt);
	}

	@Override
	public void edit(Structure dt, String fieldName) {
		editorManager.edit(dt, fieldName);
	}

	@Override
	public DataTypeManager getBuiltInDataTypesManager() {
		return dataTypeManagerHandler.getBuiltInDataTypesManager();
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
	public DataTypeManager[] getDataTypeManagers() {
		return dataTypeManagerHandler.getDataTypeManagers();
	}

	@Override
	public void closeArchive(DataTypeManager dtm) {
		dataTypeManagerHandler.closeArchive(dtm);
		provider.archiveClosed(dtm);
	}

	@Override
	public DataTypeManager openDataTypeArchive(String archiveName)
			throws IOException, DuplicateIdException {
		return dataTypeManagerHandler.openArchive(archiveName);
	}

	@Override
	public DataTypeManager openArchive(ResourceFile file, boolean acquireWriteLock)
			throws IOException, DuplicateIdException {
		Archive archive = openArchive(file.getFile(true), acquireWriteLock);
		return archive.getDataTypeManager();
	}

	@Override
	public DataTypeManager openArchive(DomainFile domainFile, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException, DuplicateIdException {
		DataTypeArchive archive = openArchive(domainFile);
		return archive.getDataTypeManager();
	}

	public List<Archive> getAllArchives() {
		return dataTypeManagerHandler.getAllArchives();
	}

	public void openProjectDataTypeArchive() {

		OpenVersionedFileDialog<DataTypeArchive> dialog = new OpenVersionedFileDialog<>(tool,
			"Open Project Data Type Archive", DataTypeArchive.class);
		dialog.setHelpLocation(new HelpLocation(HelpTopics.PROGRAM, "Open_File_Dialog"));
		dialog.addOkActionListener(ev -> {
			DomainFile domainFile = dialog.getDomainFile();
			int version = dialog.getVersion();
			if (domainFile == null) {
				dialog.setStatusText("Please choose a Project Data Type Archive");
			}
			else {
				dialog.close();
				openArchive(domainFile, version);
			}
		});

		tool.showDialog(dialog);
	}

	@Override
	public List<DataType> getFavorites() {
		return dataTypeManagerHandler.getFavoriteDataTypes();
	}

	@Override
	public DataType getRecentlyUsed() {
		return dataTypeManagerHandler.getRecentlyDataType();
	}

	@Override
	public List<DataType> getSortedDataTypeList() {
		return dataTypeManagerHandler.getDataTypeIndexer().getSortedDataTypeList();
	}

	@Override
	public void setDataTypeSelected(DataType dataType) {
		if (provider.isVisible()) {
			// this is a service method, ensure it is on the Swing thread, since it interacts with
			// Swing components
			Swing.runIfSwingOrRunLater(() -> provider.setDataTypeSelected(dataType));
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
		dataTypeManagerHandler.setRecentlyUsedDataType(dt);
	}

	@Override
	public void addDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		dataTypeManagerHandler.addDataTypeManagerChangeListener(listener);
	}

	@Override
	public void removeDataTypeManagerChangeListener(DataTypeManagerChangeListener listener) {
		dataTypeManagerHandler.removeDataTypeManagerChangeListener(listener);
	}

	@Override
	public Set<String> getPossibleEquateNames(long value) {
		return dataTypeManagerHandler.getPossibleEquateNames(value);
	}

	@Override
	public Class<?>[] getSupportedDataTypes() {
		return new Class[] { DataTypeArchive.class };
	}

	@Override
	public boolean acceptData(DomainFile[] data) {
		if (data == null || data.length == 0) {
			return false;
		}
		boolean addedArchives = false;

		for (DomainFile element : data) {
			if (element != null &&
				DataTypeArchive.class.isAssignableFrom(element.getDomainObjectClass())) {
				openArchive(element);
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

	public DataTypeArchive openArchive(DomainFile df) {
		return openArchive(df, -1);
	}

	public DataTypeArchive openArchive(final DomainFile df, final int version) {
		OpenDomainFileTask task =
			new OpenDomainFileTask(df, version, tool, DataTypeManagerPlugin.this);
		new TaskLauncher(task, tool.getToolFrame(), 0);
		return task.getArchive();
	}

	public boolean commit(DataType dataType) {
		return DataTypeSynchronizer.commit(dataTypeManagerHandler, dataType);
	}

	public boolean update(DataType dataType) {
		return DataTypeSynchronizer.update(dataTypeManagerHandler, dataType);
	}

	public boolean revert(DataType dataType) {
		return DataTypeSynchronizer.update(dataTypeManagerHandler, dataType);
	}

	public void disassociate(DataType dataTypes) {
		DataTypeSynchronizer.disassociate(dataTypes);
	}

	@Override
	public Archive openArchive(DataTypeArchive dataTypeArchive) {
		return dataTypeManagerHandler.openArchive(dataTypeArchive);
	}

	@Override
	public Archive openArchive(File file, boolean acquireWriteLock)
			throws IOException, DuplicateIdException {
		return dataTypeManagerHandler.openArchive(file, acquireWriteLock, false);
	}

	public AddressSetView getCurrentSelection() {
		return currentSelection;
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool dockingTool, ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return null;
		}
		DataTypesActionContext dtContext = (DataTypesActionContext) context;
		GTreeNode selectedNode = dtContext.getClickedNode();
		if (!(selectedNode instanceof ArchiveNode)) {
			return null;
		}

		List<DockingActionIf> actions = new ArrayList<>();

		ArchiveNode archiveNode = (ArchiveNode) selectedNode;
		Archive archive = archiveNode.getArchive();
		DataTypeManager dataTypeManager = archive.getDataTypeManager();
		if (dataTypeManager == null) {
			return null;
		}

		String group = "FGroup"; // after 'Edit'
		List<SourceArchive> sourceArchives = dataTypeManager.getSourceArchives();
		for (SourceArchive sourceArchive : sourceArchives) {
			DataTypeManager sourceDTM = dataTypeManagerHandler.getDataTypeManager(sourceArchive);
			boolean canUpdate = canUpdate(sourceArchive, sourceDTM);
			boolean canCommit = canCommit(sourceArchive, sourceDTM);
			actions.add(new SyncRefreshAction(this, dataTypeManagerHandler, dataTypeManager,
				archiveNode, sourceArchive, true));
			actions.add(new CommitAction(this, dataTypeManagerHandler, dataTypeManager, archiveNode,
				sourceArchive, canCommit));
			actions.add(new UpdateAction(this, dataTypeManagerHandler, dataTypeManager, archiveNode,
				sourceArchive, canUpdate));
			actions.add(new RevertAction(this, dataTypeManagerHandler, dataTypeManager, archiveNode,
				sourceArchive, canCommit));
			actions.add(new DisassociateAction(this, dataTypeManagerHandler, dataTypeManager,
				archiveNode, sourceArchive));
		}

		// the current actions are all pull-right actions--set their group
		for (DockingActionIf action : actions) {
			MenuData popupData = action.getPopupMenuData();
			String pullRightName = popupData.getMenuPath()[0];
			tool.setMenuGroup(new String[] { pullRightName }, group);
		}

		UpdateSourceArchiveNamesAction action =
			new UpdateSourceArchiveNamesAction(this, dataTypeManager);
		action.getPopupMenuData().setMenuGroup(group);
		actions.add(action);
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
		List<Archive> allArchives = dataTypeManagerHandler.getAllArchives();
		for (Archive archive : allArchives) {
			if (archive instanceof ProjectArchive && archive.isModifiable()) {
				domainFileList.add(((ProjectArchive) archive).getDomainFile());
			}
		}
		return domainFileList.toArray(new DomainFile[domainFileList.size()]);
	}

	@Override
	protected boolean saveData() {
		if (!ArchiveUtils.canClose(dataTypeManagerHandler.getAllFileOrProjectArchives(),
			provider.getComponent())) {
			return false;
		}
		return true;
	}
}

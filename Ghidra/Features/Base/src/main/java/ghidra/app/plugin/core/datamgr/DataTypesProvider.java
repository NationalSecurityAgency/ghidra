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
import java.awt.Point;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.event.HyperlinkEvent.EventType;
import javax.swing.tree.TreePath;

import docking.*;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.event.mouse.GMouseListenerAdapter;
import docking.menu.MultiActionDockingAction;
import docking.widgets.OptionDialog;
import docking.widgets.textpane.GHtmlTextPane;
import docking.widgets.tree.*;
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
import generic.theme.GIcon;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.plugin.core.datamgr.actions.*;
import ghidra.app.plugin.core.datamgr.actions.associate.*;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.util.ToolTipUtils;
import ghidra.app.util.datatype.DataTypeUrl;
import ghidra.framework.main.datatree.ArchiveProvider;
import ghidra.framework.main.datatree.VersionControlDataTypeArchiveUndoCheckoutAction;
import ghidra.framework.main.projectdata.actions.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeConflictHandler.ConflictResolutionPolicy;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.task.SwingUpdateManager;
import util.HistoryList;

public class DataTypesProvider extends ComponentProviderAdapter {

	private static final String TITLE = "Data Type Manager";
	private static final String POINTER_FILTER_STATE = "PointerFilterState";
	private static final String ARRAY_FILTER_STATE = "ArrayFilterState";
	private static final String CONFLICT_RESOLUTION_MODE = "ConflictResolutionMode";
	private static final String PREVIEW_WINDOW_STATE = "PreviewWindowState";
	private static final String INCLUDE_DATA_MEMBERS_IN_SEARCH = "DataMembersInSearchState";

	//
	// Preview variables and state
	//
	private JSplitPane splitPane;
	private int defaultDividerSize;
	private JScrollPane previewScrollPane;
	private JTextPane previewPane;

	private GTreeNode lastPreviewNode;
	private SwingUpdateManager previewUpdateManager =
		new SwingUpdateManager(100, () -> updatePreviewPane());

	private DataTypeArchiveGTree archiveGTree;
	private HelpLocation helpLocation;
	private DataTypeManagerPlugin plugin;

	private HistoryList<DataTypeUrl> navigationHistory = new HistoryList<>(15, url -> {
		DataType dt = url.getDataType(plugin);
		setDataTypeSelected(dt);
	});
	private MultiActionDockingAction nextAction;
	private MultiActionDockingAction previousAction;

	private ConflictHandlerModesAction conflictHandlerModesAction;
	private ToggleDockingAction filterArraysAction;
	private ToggleDockingAction filterPointersAction;
	private ToggleDockingAction previewWindowAction;
	private ToggleDockingAction includeDataMembersInSearchAction;
	private FilterOnNameOnlyAction filterOnNameOnlyAction;
	private boolean includeDataMembersInFilter;
	private boolean filterOnNameOnly;

	public DataTypesProvider(DataTypeManagerPlugin plugin, String providerName) {
		this(plugin, providerName, false);
	}

	public DataTypesProvider(DataTypeManagerPlugin plugin, String providerName,
			boolean isTransient) {
		super(plugin.getTool(), providerName, plugin.getName(), DataTypesActionContext.class);
		this.plugin = plugin;

		if (isTransient) {
			setTransient();
		}
		else {
			addToToolbar();
		}

		setTitle(TITLE);
		setIcon(new GIcon("icon.plugin.datatypes.provider"));

		navigationHistory.setAllowDuplicates(true);

		buildComponent();
		helpLocation = new HelpLocation(plugin.getName(), "Data_Type_Manager");
		addToTool();
		createLocalActions();
	}

	/**
	 * This creates all the actions for opening/creating data type archives.
	 * It also creates the action for refreshing the built-in data types
	 * from the class path.
	 */
	private void createLocalActions() {

		// Create group
		tool.setMenuGroup(new String[] { "New" }, "Create");
		addLocalAction(new CreateCategoryAction(plugin));
		DockingAction action = new CreateStructureAction(plugin);
		action.setEnabled(false);
		addLocalAction(action);

		action = new CreateUnionAction(plugin);
		action.setEnabled(false);
		addLocalAction(action);

		action = new CreateEnumAction(plugin);
		action.setEnabled(false);
		addLocalAction(action);

		action = new CreateFunctionDefinitionAction(plugin);
		action.setEnabled(false);
		addLocalAction(action);

		addLocalAction(new CreateTypeDefAction(plugin));
		addLocalAction(new CreateTypeDefFromDialogAction(plugin));

		addLocalAction(new CreatePointerAction(plugin));

		// Edit group
		addLocalAction(new CutAction(plugin));
		addLocalAction(new CopyAction(plugin));
		addLocalAction(new PasteAction(plugin));
		addLocalAction(new ReplaceDataTypeAction(plugin));
		addLocalAction(new DeleteAction(plugin));
		addLocalAction(new DeleteArchiveAction(plugin));
		addLocalAction(new RenameAction(plugin));
		addLocalAction(new EditAction(plugin));
		addLocalAction(new CreateEnumFromSelectionAction(plugin));

		// File group
		addLocalAction(new SaveArchiveAction(plugin)); // Archive
		addLocalAction(new CloseArchiveAction(plugin)); // Archive
		addLocalAction(new RemoveInvalidArchiveFromProgramAction(plugin)); // Archive

		// FileEdit group
		addLocalAction(new LockArchiveAction(plugin)); // Archive
		addLocalAction(new UnlockArchiveAction(plugin)); // Archive
		addLocalAction(new UndoArchiveTransactionAction(plugin)); // Archive
		addLocalAction(new RedoArchiveTransactionAction(plugin)); // Archive

		// Arch group
		addLocalAction(new SetArchiveArchitectureAction(plugin)); // Archive
		addLocalAction(new ClearArchiveArchitectureAction(plugin)); // Archive

		// Repository group : version control actions
		addVersionControlActions(); // Archive

		// Tree group
		addLocalAction(new CollapseAllArchivesAction(plugin)); // Tree
		addLocalAction(new ExpandAllAction(plugin)); // Tree

		// VeryLast group
		addLocalAction(new FindDataTypesByNameAction(plugin, "1"));
		addLocalAction(new FindDataTypesBySizeAction(plugin, "2"));
		addLocalAction(new FindStructuresByOffsetAction(plugin, "3"));
		addLocalAction(new FindStructuresBySizeAction(plugin, "4"));
		includeDataMembersInSearchAction = new IncludeDataTypesInFilterAction(plugin, this, "5");
		addLocalAction(includeDataMembersInSearchAction);

		filterOnNameOnlyAction = new FilterOnNameOnlyAction(plugin, this, "6");
		addLocalAction(filterOnNameOnlyAction);

		addLocalAction(new ApplyFunctionDataTypesAction(plugin)); // Tree
		addLocalAction(new CaptureFunctionDataTypesAction(plugin)); // Tree
		addLocalAction(new SetFavoriteDataTypeAction(plugin)); // Data Type
		addLocalAction(new ExportToHeaderAction(plugin)); // DataType
		addLocalAction(new ApplyEnumsAsLabelsAction(plugin)); // DataType

		// ZVeryLast group
		addLocalAction(new FindReferencesToDataTypeAction(plugin)); // DataType
		addLocalAction(new FindReferencesToFieldByNameOrOffsetAction(plugin)); // DataType
		addLocalAction(new FindBaseDataTypeAction(plugin)); // DataType
		addLocalAction(new DisplayTypeAsGraphAction(plugin));

		// toolbar actions
		previousAction = new NextPreviousDataTypeAction(this, plugin.getName(), false);
		addLocalAction(previousAction);
		nextAction = new NextPreviousDataTypeAction(this, plugin.getName(), true);
		addLocalAction(nextAction);
		addLocalAction(getFilterArraysAction());
		addLocalAction(getFilterPointersAction());
		addLocalAction(getConflictHandlerModesAction());

		// toolbar menu
		addLocalAction(new OpenArchiveAction(plugin));
		addLocalAction(new OpenProjectArchiveAction(plugin));
		addLocalAction(new CreateArchiveAction(plugin));
		addLocalAction(new CreateProjectArchiveAction(plugin));
		ToggleDockingAction previewAction = getPreviewWindowAction();
		addLocalAction(previewAction);

		// key binding only
		addLocalAction(new ClearCutAction(plugin)); // Common

		addLocalAction(new AssociateDataTypeAction(plugin));
		addLocalAction(new CommitSingleDataTypeAction(plugin));
		addLocalAction(new UpdateSingleDataTypeAction(plugin));
		addLocalAction(new RevertDataTypeAction(plugin));
		addLocalAction(new DisassociateDataTypeAction(plugin));
		addLocalAction(new EditArchivePathAction(plugin));

	}

	private void addVersionControlActions() {

		ArchiveProvider archiveProvider = () -> {
			TreePath[] selectionPaths = archiveGTree.getSelectionPaths();
			List<Archive> selectedArchives = new ArrayList<>();
			for (TreePath path : selectionPaths) {
				Object lastPathComponent = path.getLastPathComponent();
				if (lastPathComponent instanceof ProjectArchiveNode) {
					ProjectArchiveNode node = (ProjectArchiveNode) lastPathComponent;
					ProjectArchive archive = (ProjectArchive) node.getArchive();
					selectedArchives.add(archive);
				}
			}
			return selectedArchives;
		};

		VersionControlAddAction addAction = new VersionControlAddAction(plugin);
		addAction.setEnabled(false);

		VersionControlCheckOutAction checkOutAction = new VersionControlCheckOutAction(plugin);
		checkOutAction.setEnabled(false);

		VersionControlUpdateAction updateAction = new VersionControlUpdateAction(plugin);
		updateAction.setEnabled(false);

		VersionControlCheckInAction checkInAction =
			new VersionControlCheckInAction(plugin, archiveGTree);
		checkInAction.setEnabled(false);

		VersionControlDataTypeArchiveUndoCheckoutAction undoCheckOutAction =
			new VersionControlDataTypeArchiveUndoCheckoutAction(plugin, archiveProvider);
		undoCheckOutAction.setEnabled(false);

		VersionControlShowHistoryAction showHistoryAction =
			new VersionControlShowHistoryAction(plugin);
		showHistoryAction.setEnabled(false);

		VersionControlViewCheckOutAction viewCheckOutsAction =
			new VersionControlViewCheckOutAction(plugin);
		viewCheckOutsAction.setEnabled(false);

		addAction.setToolBarData(null);
		checkOutAction.setToolBarData(null);
		updateAction.setToolBarData(null);
		checkInAction.setToolBarData(null);

		addLocalAction(addAction);
		addLocalAction(checkOutAction);
		addLocalAction(updateAction);
		addLocalAction(checkInAction);
		addLocalAction(undoCheckOutAction);
		addLocalAction(showHistoryAction);
		addLocalAction(viewCheckOutsAction);
	}

	private boolean hasFilter() {
		return archiveGTree.isFiltered();
	}

	public boolean isFilteringPointers() {
		return filterPointersAction.isSelected();
	}

	public boolean isFilteringArrays() {
		return filterArraysAction.isSelected();
	}

	private ToggleDockingAction getFilterPointersAction() {
		if (filterPointersAction == null) {
			filterPointersAction = new FilterPointersAction(plugin);
			archiveGTree.enablePointerFilter(filterPointersAction.isSelected());
		}

		return filterPointersAction;
	}

	private ToggleDockingAction getFilterArraysAction() {
		if (filterArraysAction == null) {
			filterArraysAction = new FilterArraysAction(plugin);
			archiveGTree.enableArrayFilter(filterArraysAction.isSelected());
		}

		return filterArraysAction;
	}

	private ConflictHandlerModesAction getConflictHandlerModesAction() {
		if (conflictHandlerModesAction == null) {
			conflictHandlerModesAction = new ConflictHandlerModesAction(plugin);
		}
		return conflictHandlerModesAction;
	}

	private ToggleDockingAction getPreviewWindowAction() {
		if (previewWindowAction == null) {
			previewWindowAction = new PreviewWindowAction(plugin, this);
		}
		return previewWindowAction;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		GTreeNode clickedNode = null;
		boolean isToolbarAction = true;
		if (event != null) {
			Object source = event.getSource();
			if (source instanceof JTextField || source instanceof JTextPane) {
				Component component = (Component) source;
				return new DefaultActionContext(this, source, component);
			}

			Point point = event.getPoint();
			clickedNode = archiveGTree.getNodeForLocation(point.x, point.y);
			isToolbarAction = false;
		}
		else {
			// Called via a keybinding; use the selected node in the tree to represent the clicked
			// node.  This allows users to use a keybinding to show the context menu and have all
			// actions installed.
			TreePath path = archiveGTree.getSelectionPath();
			if (path != null) {
				clickedNode = (GTreeNode) path.getLastPathComponent();
			}
		}

		return new DataTypesActionContext(this, plugin.getProgram(), archiveGTree, clickedNode,
			isToolbarAction);
	}

	@Override // overridden to handle special logic in plugin
	public void closeComponent() {
		super.closeComponent();
		if (isTransient()) {
			dispose();
		}
	}

	private void buildComponent() {
		splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

		archiveGTree = new DataTypeArchiveGTree(plugin);
		archiveGTree.addMouseListener(new GMouseListenerAdapter() {

			private GTreeNode lastClickedNode;

			@Override
			public void doubleClickTriggered(MouseEvent e) {

				Point point = e.getPoint();
				GTreeNode clickedNode = archiveGTree.getNodeForLocation(point.x, point.y);
				if (clickedNode == null) {
					return;
				}

				if (clickedNode != lastClickedNode) {
					// this can happen when the tree moves during a double-click
					return;
				}

				editNode(clickedNode);
			}

			@Override
			public void mouseClicked(MouseEvent e) {
				super.mouseClicked(e);
				Point point = e.getPoint();
				GTreeNode clickedNode = archiveGTree.getNodeForLocation(point.x, point.y);
				lastClickedNode = clickedNode;
			}
		});

		archiveGTree.addGTModelListener(new TreeModelListener() {
			@Override
			public void treeStructureChanged(TreeModelEvent e) {
				previewUpdateManager.update();
			}

			@Override
			public void treeNodesRemoved(TreeModelEvent e) {
				previewUpdateManager.update();
			}

			@Override
			public void treeNodesInserted(TreeModelEvent e) {
				previewUpdateManager.update();
			}

			@Override
			public void treeNodesChanged(TreeModelEvent e) {
				previewUpdateManager.update();
			}
		});

		archiveGTree.addGTreeSelectionListener(e -> {

			TreePath path = e.getNewLeadSelectionPath();
			DataType dataType = getDataTypeFrom(path);

			dataTypeSelected(e.getEventOrigin(), dataType);
		});

		buildPreviewPane();

		archiveGTree.addGTreeSelectionListener(e -> previewUpdateManager.update());

		splitPane.setLeftComponent(archiveGTree);
		splitPane.setRightComponent(null);
		splitPane.setResizeWeight(0.5);

		// We don't remove the split pane, just empty the bottom out when not using it.  Set the
		// divider size to 0 so it is not visible when we are not using the bottom half.
		defaultDividerSize = splitPane.getDividerSize();
		splitPane.setDividerSize(0);
	}

	private void buildPreviewPane() {
		previewPane = new GHtmlTextPane();
		previewPane.setEditable(false);
		previewPane.setBorder(BorderFactory.createLoweredBevelBorder());
		previewPane.setBackground(Colors.BACKGROUND);

		// This listener responds to the user hovering/clicking the preview's hyperlinks
		previewPane.addHyperlinkListener(event -> {

			EventType type = event.getEventType();
			DataType dt = locateDataType(event);
			if (dt == null) {
				// shouldn't happen
				Msg.debug(this, "Could not find data type for " + event.getDescription());
				plugin.setStatus("Could not find data type for " + event.getDescription());
				return;
			}

			if (type == EventType.ACTIVATED) {
				setDataTypeSelected(dt);
			}
			else if (type == EventType.ENTERED) {
				previewPane.setToolTipText(dt.getCategoryPath().toString());
			}
			else if (type == EventType.EXITED) {
				previewPane.setToolTipText(null);
			}

		});

		previewScrollPane = new JScrollPane(previewPane);

		DockingWindowManager.getHelpService()
				.registerHelp(previewScrollPane,
					new HelpLocation("DataTypeManagerPlugin", "Preview_Window"));
	}

	private DataType locateDataType(HyperlinkEvent event) {
		String href = event.getDescription();

		DataTypeUrl url = null;
		try {
			url = new DataTypeUrl(href);
		}
		catch (IllegalArgumentException e) {
			Msg.debug(this, "Could not parse Data Type URL '" + href + "'", e);
			return null;
		}

		return url.getDataType(plugin);
	}

	private void updatePreviewPane() {
		if (!previewPane.isShowing()) {
			return;
		}

		TreePath path = archiveGTree.getSelectionPath();
		GTreeNode node = null;
		if (path == null) {
			if (lastPreviewNode == null) {
				return; // never shown a preview--nothing to update
			}
			node = lastPreviewNode;
		}
		else {
			node = (GTreeNode) path.getLastPathComponent();
			lastPreviewNode = node;
		}

		if (node instanceof DataTypeNode) {
			showDataTypePreview((DataTypeNode) node);
			return;
		}

		String toolTip = node.getToolTip();
		if (toolTip != null) {
			// Make the text big enough to see easily
			toolTip = "<html><font size=\"5\">" + toolTip + "</font>";
		}

		previewPane.setText(toolTip);
		previewPane.setCaretPosition(0);
	}

	private void showDataTypePreview(DataTypeNode dataTypeNode) {

		DataType dataType = dataTypeNode.getDataType();
		if (dataType.isDeleted()) {
			// this can happen during an undo
			lastPreviewNode = null;
			return;
		}

		String toolTipText = ToolTipUtils.getFullToolTipText(dataType);
		String updated = HTMLUtilities.convertLinkPlaceholdersToHyperlinks(toolTipText);
		previewPane.setText(updated);
		previewPane.setCaretPosition(0);
	}

	void dispose() {
		previewUpdateManager.dispose();
		archiveGTree.dispose();
		navigationHistory.clear();
	}

	@Override
	public HelpLocation getHelpLocation() {
		return helpLocation;
	}

	private static DataType updateDataType(CategoryPath path, String dataTypeName,
			ArchiveNode archiveNode) {
		DataTypeManager dataTypeManager = archiveNode.getArchive().getDataTypeManager();
		Category category = dataTypeManager.getCategory(path);
		return category.getDataType(dataTypeName);
	}

	private boolean getWriteLock(DataTypeManagerPlugin dataTypePlugin, ArchiveNode archiveNode) {
		if (!isOkToLock()) {
			return false;
		}
		GTree tree = dataTypePlugin.getProvider().getGTree();
		GTreeState state = tree.getTreeState();
		if (!ArchiveUtils.lockArchive((FileArchive) archiveNode.getArchive())) {
			return false;
		}
		tree.restoreTreeState(state);

		return true;
	}

	private boolean needsWriteLock(ArchiveNode archiveNode) {
		if (archiveNode instanceof FileArchiveNode) {
			FileArchiveNode fileArchiveNode = (FileArchiveNode) archiveNode;
			return !fileArchiveNode.hasWriteLock();
		}
		return false;
	}

	private boolean isOkToLock() {
		return (OptionDialog.showYesNoDialog(archiveGTree, "Open Archive for Edit?",
			"Archive file is not modifiable.\nDo you want to open for edit?") == OptionDialog.OPTION_ONE);
	}

//==================================================================================================
// Helper Methods
//==================================================================================================

	public void editNode(GTreeNode node) {
		if (!(node instanceof DataTypeNode)) {
			return;
		}
		DataTypeNode dataTypeNode = (DataTypeNode) node;

		if (!dataTypeNode.hasCustomEditor()) {
			return;
		}

		DataType dataType = dataTypeNode.getDataType();
		dataType = DataTypeUtils.getBaseDataType(dataType);
		CategoryPath path = dataType.getCategoryPath();
		String dataTypeName = dataType.getName();
		ArchiveNode archiveNode = dataTypeNode.getArchiveNode();

		if (archiveNode instanceof ProjectArchiveNode && !archiveNode.isModifiable()) {
			ProjectArchiveNode projectArchive = (ProjectArchiveNode) archiveNode;
			if (projectArchive.getDomainFile().isReadOnly()) {
				Msg.showInfo(getClass(), archiveGTree, "Read-Only Archive",
					"You may not edit data type within a read-only project archive.");
			}
			else {
				Msg.showInfo(getClass(), archiveGTree, "Archive Not Checked Out",
					"You must checkout this archive before you may edit data types.");
			}
			return;
		}

		// must get write lock before we can edit
		if (needsWriteLock(archiveNode)) {
			if (!getWriteLock(plugin, archiveNode)) {
				return;
			}
			dataType = updateDataType(path, dataTypeName, archiveNode);
		}

		plugin.getEditorManager().edit(dataType);
	}

	void restore(SaveState saveState) {
		boolean filterPointers = saveState.getBoolean(POINTER_FILTER_STATE, true);
		boolean filterArrays = saveState.getBoolean(ARRAY_FILTER_STATE, true);
		ConflictResolutionPolicy conflictMode;
		try {
			conflictMode =
				ConflictResolutionPolicy.valueOf(saveState.getString(CONFLICT_RESOLUTION_MODE,
					ConflictResolutionPolicy.RENAME_AND_ADD.toString()));
		}
		catch (IllegalArgumentException e) {
			conflictMode = ConflictResolutionPolicy.RENAME_AND_ADD;
		}
		getFilterPointersAction().setSelected(filterPointers);
		getFilterArraysAction().setSelected(filterArrays);
		getConflictHandlerModesAction().setCurrentActionStateByUserData(conflictMode);

		archiveGTree.enableArrayFilter(filterArrays);
		archiveGTree.enablePointerFilter(filterPointers);

		boolean previewWindowVisible = saveState.getBoolean(PREVIEW_WINDOW_STATE, false);
		getPreviewWindowAction().setSelected(previewWindowVisible);

		boolean dataMembersInSearch = saveState.getBoolean(INCLUDE_DATA_MEMBERS_IN_SEARCH, false);
		includeDataMembersInSearchAction.setSelected(dataMembersInSearch);
	}

	void save(SaveState saveState) {
		saveState.putBoolean(POINTER_FILTER_STATE, getFilterPointersAction().isSelected());
		saveState.putBoolean(ARRAY_FILTER_STATE, getFilterArraysAction().isSelected());
		saveState.putString(CONFLICT_RESOLUTION_MODE,
			getConflictHandlerModesAction().getCurrentUserData().toString());
		saveState.putBoolean(PREVIEW_WINDOW_STATE, getPreviewWindowAction().isSelected());
		saveState.putBoolean(INCLUDE_DATA_MEMBERS_IN_SEARCH,
			includeDataMembersInSearchAction.isSelected());
	}

	public DataTypeArchiveGTree getGTree() {
		if (archiveGTree == null) {
			buildComponent();
		}
		return archiveGTree;
	}

	void domainObjectRestored(DataTypeManagerDomainObject domainObject) {
		if (archiveGTree == null) {
			return; // nothing to update
		}
		if (domainObject instanceof Program) {
			Program program = (Program) domainObject;
			Program programInTree = plugin.getProgram(); // May be null.
			if (program == programInTree) {
				DataTypeArchiveGTree gTree = getGTree();
				ArchiveNode node = getProgramArchiveNode();
				// don't know how this can be null, but a mysterious stack trace showed it.
				if (node != null) {
					GTreeState state = gTree.getTreeState(node);
					node.structureChanged();
					gTree.restoreTreeState(state);
				}
			}
		}
		else if (domainObject instanceof DataTypeArchive) {
			DataTypeArchive dataTypeArchive = (DataTypeArchive) domainObject;
			DataTypeArchiveGTree gTree = getGTree();
			ArchiveNode node = getDataTypeArchiveNode(dataTypeArchive);
			if (node != null) {
				GTreeState state = gTree.getTreeState(node);
				node.structureChanged();
				gTree.restoreTreeState(state);
			}
		}
	}

	private ArchiveNode getProgramArchiveNode() {
		GTreeNode rootNode = getGTree().getModelRoot();
		List<GTreeNode> children = rootNode.getChildren();
		for (GTreeNode node : children) {
			ArchiveNode archiveNode = (ArchiveNode) node;
			Archive archive = archiveNode.getArchive();
			if (archive instanceof ProgramArchive) {
				return archiveNode;
			}
		}
		return null;
	}

	private ArchiveNode getDataTypeArchiveNode(DataTypeArchive dataTypeArchive) {
		GTreeNode rootNode = getGTree().getModelRoot();
		List<GTreeNode> children = rootNode.getChildren();
		for (GTreeNode node : children) {
			ArchiveNode archiveNode = (ArchiveNode) node;
			Archive archive = archiveNode.getArchive();
			if (archive instanceof ProjectArchive) {
				ProjectArchive projectArchive = (ProjectArchive) archive;
				if (projectArchive.getDataTypeManager() == dataTypeArchive.getDataTypeManager()) {
					return archiveNode;
				}
			}
		}
		return null;
	}

	public void setFilterText(String text) {
		getGTree().setFilterText(text);
	}

	/**
	 * Selects the given data type in the tree of data types.  This method will cause the
	 * data type tree to come to the front, scroll to the data type and then to select the tree
	 * node that represents the data type.  If the dataType parameter is null, then the tree
	 * selection will be cleared.
	 *
	 * @param dataType the data type to select; may be null
	 */
	public void setDataTypeSelected(DataType dataType) {
		DataTypeArchiveGTree gTree = getGTree();
		if (dataType == null) { // clear the selection
			gTree.getSelectionModel().clearSelection();
			return;
		}

		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		if (dataTypeManager == null) {
			return;
		}

		Category category = dataTypeManager.getCategory(dataType.getCategoryPath());
		ArchiveRootNode rootNode = (ArchiveRootNode) gTree.getViewRoot();
		ArchiveNode archiveNode = rootNode.getNodeForManager(dataTypeManager);
		if (archiveNode == null) {
			plugin.setStatus("Cannot find archive '" + dataTypeManager.getName() + "'.  It may " +
				"be filtered out of view or may have been closed (Data Type Manager)");
			return;
		}

		// Note: passing 'true' here forces a load if needed.  This could be slow for programs
		//       with many types.  If this locks the UI, then put this work into a GTreeTask.
		CategoryNode node = archiveNode.findCategoryNode(category, true);
		if (node == null) {
			return;
		}

		DataTypeNode dataTypeNode = node.getNode(dataType);
		if (dataTypeNode == null) {

			if (hasFilter()) {
				plugin.setStatus("Unable to find " + dataType.getName() +
					".  It may be filtered out of view.  (Data Type Manager)");
			}
			return;
		}

		gTree.setSelectedNode(dataTypeNode);
		gTree.scrollPathToVisible(dataTypeNode.getTreePath());
		contextChanged();
	}

	/**
	 * Returns a list of all the data types selected in the data types tree
	 * @return a list of all the data types selected in the data types tree
	 */
	public List<DataType> getSelectedDataTypes() {
		List<DataType> selectedDataTypes = new ArrayList<>();
		DataTypeArchiveGTree gTree = getGTree();
		for (TreePath path : gTree.getSelectionPaths()) {
			Object node = path.getLastPathComponent();
			if (node instanceof DataTypeNode) {
				DataType dataType = ((DataTypeNode) node).getDataType();
				if (dataType != null) {
					selectedDataTypes.add(dataType);
				}
			}
		}
		return selectedDataTypes;
	}

	// this is called from the action
	public void setIncludeDataTypeMembersInFilterCallback(boolean newValue) {
		includeDataMembersInFilter = newValue;
		archiveGTree.updateDataTransformer(this);
	}

	// this is called from the action
	public void setFilterOnNameOnlyCallback(boolean newValue) {
		filterOnNameOnly = newValue;
		archiveGTree.updateDataTransformer(this);
	}

	public void setIncludeDataTypeMembersInFilter(boolean newValue) {
		includeDataMembersInSearchAction.setSelected(newValue);
	}

	public void setFilterOnNameOnly(boolean newValue) {
		filterOnNameOnlyAction.setSelected(newValue);
	}

	public void setFilteringArrays(boolean b) {
		archiveGTree.enableArrayFilter(b);
	}

	public void setFilteringPointers(boolean b) {
		archiveGTree.enablePointerFilter(b);
	}

	public boolean isIncludeDataMembersInSearch() {
		return includeDataMembersInFilter;
	}

	public boolean isFilterOnNameOnly() {
		return filterOnNameOnly;
	}

	@Override
	public JComponent getComponent() {
		return splitPane;
	}

	// callback from the action
	public void setPreviewWindowVisible(boolean visible) {
		JComponent component = visible ? previewScrollPane : null;
		splitPane.setRightComponent(component);

		int size = visible ? defaultDividerSize : 0;
		splitPane.setDividerSize(size);

		if (!visible) {
			return;
		}

		// update the preview contents
		TreePath path = archiveGTree.getSelectionPath();
		if (path == null) {
			return;
		}

		GTreeNode node = (GTreeNode) path.getLastPathComponent();
		previewPane.setText(node.getToolTip());
	}

	String getPreviewText() {
		return previewPane.getText();
	}

	void programClosed() {
		archiveGTree.cancelWork();
	}

	void archiveClosed(DataTypeManager dtm) {
		dataTypeManagerChanged(dtm);
	}

	void archiveChanged(Archive archive) {
		DataTypeManager dtm = archive.getDataTypeManager();
		dataTypeManagerChanged(dtm);
	}

	private void dataTypeManagerChanged(DataTypeManager dtm) {

		if (lastPreviewNode == null || !(lastPreviewNode instanceof DataTypeNode)) {
			return;
		}

		DataTypeNode dtNode = (DataTypeNode) lastPreviewNode;
		DataType dt = dtNode.getDataType();
		DataTypeManager dtManager = dt.getDataTypeManager();

		// note: compare using name; an equality check will fail if the manager is reloaded
		if (dtm.getName().equals(dtManager.getName())) {
			lastPreviewNode = null;
		}
	}

	void programRenamed() {
		ArchiveRootNode rootNode = (ArchiveRootNode) archiveGTree.getModelRoot();
		List<GTreeNode> allChildren = rootNode.getChildren();
		for (GTreeNode node : allChildren) {
			ArchiveNode archiveNode = (ArchiveNode) node;
			if (archiveNode.getArchive() instanceof ProgramArchive) {
				archiveNode.nodeChanged();
				return;
			}
		}
	}

	DataTypeConflictHandler getConflictHandler() {
		ConflictResolutionPolicy conflictMode =
			getConflictHandlerModesAction().getCurrentUserData();
		return conflictMode.getHandler();
	}

	DataTypeManagerPlugin getPlugin() {
		return plugin;
	}

	private DataType getDataTypeFrom(TreePath path) {
		if (path == null) {
			return null;
		}

		GTreeNode node = (GTreeNode) path.getLastPathComponent();
		if (!(node instanceof DataTypeNode)) {
			return null; // must be a category or the root node
		}

		DataTypeNode dtNode = (DataTypeNode) node;
		DataType dt = dtNode.getDataType();
		return dt;
	}

	HistoryList<DataTypeUrl> getNavigationHistory() {
		return navigationHistory;
	}

	MultiActionDockingAction getPreviousAction() {
		return previousAction;
	}

	MultiActionDockingAction getNextAction() {
		return nextAction;
	}

	JTextPane getPreviewPane() {
		return previewPane;
	}

	private void dataTypeSelected(EventOrigin eventOrigin, DataType dt) {

		if (eventOrigin == EventOrigin.INTERNAL_GENERATED) {
			return; // Ignore events from the GTree's housekeeping
		}

		// the data type is null when a non-data type node is selected, like a category node
		if (dt == null) {
			return;
		}

		navigationHistory.add(new DataTypeUrl(dt));
		contextChanged();
	}

}

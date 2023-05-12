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
package ghidra.app.plugin.core.data;

import java.util.*;

import javax.swing.tree.TreePath;

import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.data.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.compositeeditor.*;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeTreeNode;
import ghidra.app.services.DataService;
import ghidra.app.services.DataTypeManagerService;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.SwingUpdateManager;

/**
 * This plugin provides a generic method for: Applying installed data types to
 * create data for a program Changing an existing Data item's properties.
 *
 * Currently any DataTypeProvider registered in the ServiceRegistry is displayed
 * in the MouseRight Pop-up menu over an undefined data item. Once a Data item
 * is defined, the properties associated with the data item that can be set are
 * displayed in the MouseRight Pop-up menu.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Create Data in listing",
	description = "Provides many actions for setting, changing and deleting data in the listing display.",
	servicesRequired = { DataTypeManagerService.class },
	servicesProvided = { DataService.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class DataPlugin extends Plugin implements DataService {

	final static int BACKGROUND_SELECTION_THRESHOLD = 2048;
	final static DataType POINTER_DATA_TYPE = new PointerDataType();

	private static final String BASIC_DATA_GROUP = "BasicData";
	private static final String DATA_MENU_POPUP_PATH = "Data";
	private static final String[] EDIT_DATA_TYPE_POPUP_PATH =
		{ DATA_MENU_POPUP_PATH, "Edit Data Type..." };
	private static final String[] DATA_SETTINGS_POPUP_PATH =
		{ DATA_MENU_POPUP_PATH, "Settings..." };
	private static final String[] DEFAULT_SETTINGS_POPUP_PATH =
		{ DATA_MENU_POPUP_PATH, "Default Settings..." };
	private static final String[] DATATYPE_SETTINGS_POPUP_PATH = { "Settings..." };
	private static final String[] CHOOSE_DATA_TYPE_POPUP_PATH =
		{ DATA_MENU_POPUP_PATH, "Choose Data Type..." };

	private DataTypeManagerService dtmService;

	private DataAction pointerAction;
	private DataAction recentlyUsedAction;
	private DockingAction editDataTypeAction;
	private CreateStructureAction createStructureAction;
	private CreateArrayAction createArrayAction;
	private RenameDataFieldAction renameDataFieldAction;

	private List<DataAction> favoriteActions = new ArrayList<>();

	private ChooseDataTypeAction chooseDataTypeAction;

	private DataTypeManagerChangeListenerAdapter adapter;

	private SwingUpdateManager favoritesUpdateManager;

	public DataPlugin(PluginTool tool) {
		super(tool);

		addActions();

		favoritesUpdateManager = new SwingUpdateManager(1000, 30000, () -> updateFavoriteActions());
	}

	@Override
	protected void init() {
		initializeServices();
		addCycleGroupActions();
		updateFavoriteActions();
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			favoritesUpdateManager.updateLater();
		}
	}

	/**
	 * Add actions
	 */
	private void addActions() {
		recentlyUsedAction = new RecentlyUsedAction(this);
		recentlyUsedAction.setEnabled(false);

		tool.addAction(recentlyUsedAction);

		createStructureAction = new CreateStructureAction(this);
		tool.addAction(createStructureAction);

		createArrayAction = new CreateArrayAction(this);
		tool.addAction(createArrayAction);

		renameDataFieldAction = new RenameDataFieldAction(this);
		tool.addAction(renameDataFieldAction);

		pointerAction = new PointerDataAction(this);
		tool.addAction(pointerAction);

		// Data instance settings action based upon data selection in listing
		new ActionBuilder("Data Settings", getName())
				.sharedKeyBinding()
				.popupMenuPath(DATA_SETTINGS_POPUP_PATH)
				.popupMenuGroup("Settings")
				.withContext(ListingActionContext.class)
				.enabledWhen(context -> isDataTypeSettingsAllowed(context, false))
				.onAction(context -> dataSettingsCallback(context))
				.buildAndInstall(tool);

		// Default settings action based upon data selection in listing
		new ActionBuilder("Default Settings", getName())
				.sharedKeyBinding()
				.popupMenuPath(DEFAULT_SETTINGS_POPUP_PATH)
				.popupMenuGroup("Settings")
				.withContext(ListingActionContext.class)
				.enabledWhen(context -> isDataTypeSettingsAllowed(context, true))
				.onAction(context -> editDefaultDataSettings(context))
				.buildAndInstall(tool);

		// Default settings action for selected datatypes from datatype manager
		new ActionBuilder("Default Settings", getName())
				.sharedKeyBinding()
				.popupMenuPath(DATATYPE_SETTINGS_POPUP_PATH)
				.popupMenuGroup("Settings")
				.withContext(DataTypesActionContext.class)
				.enabledWhen(context -> isDefaultDataTypeSettingsAllowed(context))
				.onAction(context -> editDefaultDataTypeSettings(context))
				.buildAndInstall(tool);

		// Default settings action for composite editor components (Program-based)
		new ActionBuilder("Default Settings", getName())
				.sharedKeyBinding()
				.popupMenuPath(DATATYPE_SETTINGS_POPUP_PATH)
				.popupMenuGroup("Settings")
				.withContext(ComponentProgramActionContext.class)
				.enabledWhen(context -> isDefaultComponentSettingsAllowed(context))
				.onAction(context -> editDefaultComponentSettings(context))
				.buildAndInstall(tool);

		// Default settings action for composite editor components (stand-alone archive)
		new ActionBuilder("Default Settings", getName())
				.sharedKeyBinding()
				.popupMenuPath(DATATYPE_SETTINGS_POPUP_PATH)
				.popupMenuGroup("Settings")
				.withContext(ComponentStandAloneActionContext.class)
				.enabledWhen(context -> isDefaultComponentSettingsAllowed(context))
				.onAction(context -> editDefaultComponentSettings(context))
				.buildAndInstall(tool);

		editDataTypeAction = new ActionBuilder("Edit Data Type", getName())
				.popupMenuPath(EDIT_DATA_TYPE_POPUP_PATH)
				.popupMenuGroup("BasicData")
				.withContext(ListingActionContext.class)
				.enabledWhen(c -> {
					DataType editableDt = getEditableDataTypeFromContext(c);
					if (editableDt != null) {
						editDataTypeAction.setHelpLocation(
							dtmService.getEditorHelpLocation(editableDt));
						return true;
					}
					return false;
				})
				.onAction(c -> editDataTypeCallback(c))
				.helpLocation(new HelpLocation("DataTypeEditors", "Structure_Editor"))
				.buildAndInstall(tool);

		chooseDataTypeAction = new ChooseDataTypeAction(this);
		chooseDataTypeAction.setEnabled(false);

		chooseDataTypeAction.setPopupMenuData(
			new MenuData(CHOOSE_DATA_TYPE_POPUP_PATH, BASIC_DATA_GROUP));
		chooseDataTypeAction.setEnabled(true);
		chooseDataTypeAction.setHelpLocation(
			new HelpLocation("DataTypeEditors", "DataTypeSelectionDialog"));
		tool.addAction(chooseDataTypeAction);
	}

	/**
	 * Initialize services used
	 */
	private void initializeServices() {

		dtmService = tool.getService(DataTypeManagerService.class);
		if (dtmService == null) {
			throw new AssertException("DataTypeManagerService was not found!");
		}

		// install listener for data type changes
		adapter = new DataTypeManagerChangeListenerAdapter() {
			@Override
			public void favoritesChanged(DataTypeManager dtm, DataTypePath path,
					boolean isFavorite) {
				favoritesUpdateManager.update();
			}
		};
		dtmService.addDataTypeManagerChangeListener(adapter);
	}

	DataType getEditableDataTypeFromContext(ListingActionContext context) {
		ProgramSelection selection = context.getSelection();
		Program program = context.getProgram();
		Data data = null;
		if (selection != null && !selection.isEmpty()) {
			Listing listing = program.getListing();
			boolean isDataOnly = !listing.getInstructions(selection, true).hasNext();
			if (isDataOnly) {
				data = getDataUnit(context);
			}
		}
		else {
			data = getDataUnit(context);
		}

		return getEditableDataType(data);
	}

	private DataType getEditableDataType(Data data) {
		if (data == null || dtmService == null) {
			return null;
		}

		DataType baseDt = data.getBaseDataType();
		if (dtmService.isEditable(baseDt)) {
			return baseDt;
		}

		Data pdata = data.getParent();
		if (pdata != null) {
			baseDt = pdata.getBaseDataType();
			if (dtmService.isEditable(baseDt)) {
				return baseDt;
			}
		}
		return null;
	}

	@Override
	public boolean createData(DataType dt, ListingActionContext context,
			boolean stackPointers, boolean enableConflictHandling) {
// TODO: conflict handler (i.e., removal of other conflicting data not yet supported)
		ProgramLocation location = context.getLocation();
		if (!(location instanceof CodeUnitLocation)) {
			return false;
		}

		return doCreateData(context, dt, stackPointers);
	}

	/*
	 * This version uses the ListingActionContext and does not depend on any plugin's currentProgram
	 */
	boolean doCreateData(ListingActionContext context, DataType dt, boolean stackPointers) {
		ProgramSelection selection = context.getSelection();
		ProgramLocation location = context.getLocation();
		Program program = context.getProgram();

		dt = dt.clone(program.getDataTypeManager());
		boolean didCreateData = false;
		if (selection != null && !selection.isEmpty()) {
			didCreateData = createDataForSelection(program, dt, stackPointers, selection);
		}
		else if (location != null) {
			didCreateData = createDataAtLocation(program, dt, stackPointers, location);
		}

		updateRecentlyUsed(dt);
		return didCreateData;
	}

	private boolean createDataAtLocation(Program program, DataType dt, boolean stackPointers,
			ProgramLocation location) {
		Address start = location.getAddress();
		int[] startPath = location.getComponentPath();
		Command cmd;
		if (startPath != null && startPath.length != 0) {
			cmd = new CreateDataInStructureCmd(start, startPath, dt, stackPointers);
		}
		else {
			if (!checkEnoughSpace(program, start, dt, stackPointers)) {
				return false;
			}
			cmd = new CreateDataCmd(start, true, stackPointers, dt);
		}
		return getTool().execute(cmd, program);
	}

	private boolean createDataForSelection(Program program, DataType dt, boolean stackPointers,
			ProgramSelection selection) {
		BackgroundCommand cmd;
		Address start = selection.getMinAddress();
		InteriorSelection interSel = selection.getInteriorSelection();
		if (interSel != null) {
			int[] startPath = interSel.getFrom().getComponentPath();

			int length = (int) selection.getNumAddresses(); // interior selections can't be that big
			cmd =
				new CreateDataInStructureBackgroundCmd(start, startPath, length, dt, stackPointers);
		}
		else {
			cmd = new CreateDataBackgroundCmd(selection, dt, true);
		}

		boolean didCreateData = false;
		if (selection.getNumAddresses() < BACKGROUND_SELECTION_THRESHOLD) {
			didCreateData = getTool().execute(cmd, program);
		}
		else {
			getTool().executeBackgroundCommand(cmd, program);
		}
		return didCreateData;
	}

	private boolean checkEnoughSpace(Program program, Address start, DataType dataType,
			boolean stackingEnabled) {

		Listing listing = program.getListing();
		Data data = listing.getDataAt(start);
		if (data == null) {
			tool.setStatusInfo("Invalid data location.  Cannot create data at " + start + '.');
			return false;
		}

		if (stackingEnabled && canConvertPointer(dataType, data)) {
			return true;
		}

		int newSize = getDataTypeSize(program, dataType, start);
		if (newSize == 1) {
			return true;
		}

		if (newSize <= 0) {
			tool.setStatusInfo(
				"Invalid data location.  Unable to resolve data length at " + start + " for " +
					dataType.getName());
			return false;
		}

		Address end = null;
		try {
			end = start.addNoWrap(newSize - 1);
		}
		catch (AddressOverflowException e) {
			tool.setStatusInfo("Invalid data location.  Not enough space at " + start + " for " +
				newSize + " bytes.");
			return false;
		}

		if (instructionExists(listing, dataType, start, end)) {
			tool.setStatusInfo("Invalid data location.  Instruction exists at " + start + '.');
			return false;
		}

		// See if the Data will fit within the block of memory where it starts.
		MemoryBlock memBlock = program.getMemory().getBlock(start);
		Address blockMaxAddress = memBlock.getEnd();
		if (blockMaxAddress.compareTo(end) < 0) {
			tool.setStatusInfo("Create " + dataType.getName() +
				" failed: Not enough room in memory block containing address " + start +
				" which ends at " + blockMaxAddress + ".");
			return false;
		}

		// Ignore any sized undefined data types until we get to a defined data type.
		// If only sized Undefined types are found then overwrite them.
		Data definedData =
			DataUtilities.getNextNonUndefinedDataAfter(program, start, blockMaxAddress);
		if (dataExists(program, dataType, definedData, start, end)) {
			return false; // status updated in 'dataExists()' call
		}

		return true;
	}

	private boolean canConvertPointer(DataType dataType, Data existingData) {

		if (!existingData.isDefined()) {
			return false;
		}

		if (dataType instanceof FactoryDataType) {
			return false;
		}

		if (dataType instanceof Pointer) {
			return false;
		}

		DataType existingDT = existingData.getDataType();
		return existingDT instanceof Pointer;
	}

	private boolean dataExists(Program program, DataType dataType, Data definedData, Address start,
			Address end) {

		if (definedData == null) {
			return false;
		}

		if (definedData.getMinAddress().compareTo(end) > 0) {
			return false;
		}

		//@formatter:off
		int resp =
			OptionDialog.showYesNoCancelDialog(tool.getActiveWindow(), "Data Conflict",
				"Data applied from " + start + " to " + end +
				"\nconflicts with existing defined data!\n\n" +
				"Clear conflicting data?");
		//@formatter:on

		if (resp != OptionDialog.YES_OPTION) {
			tool.setStatusInfo("Create " + dataType.getName() + " failed: Data exists at address " +
				definedData.getMinAddress() + " to " + definedData.getMaxAddress());
			return true; // data exists--don't overwrite
		}

		return false; // OK to clear the existing data
	}

	private boolean instructionExists(Listing listing, DataType dataType, Address start,
			Address end) {

		Instruction instruction = listing.getInstructionAfter(start);
		if (instruction == null) {
			return false;
		}

		String dtName = dataType.getName();
		Address minAddress = instruction.getMinAddress();
		if (minAddress.compareTo(end) <= 0) {
			tool.setStatusInfo("Create " + dtName + " failed: Instruction exists at address " +
				minAddress + " to " + instruction.getMaxAddress());
			return true;
		}
		return false;
	}

	private int getDataTypeSize(Program program, DataType dataType, Address start) {

		int newSize = dataType.getLength();
		if (newSize >= 0) {
			return newSize;
		}

		DataTypeInstance dataTypeInstance = DataTypeInstance.getDataTypeInstance(dataType,
			new DumbMemBufferImpl(program.getMemory(), start), false);
		if (dataTypeInstance == null) {
			tool.setStatusInfo("Unallowed data type at " + start + ": " + dataType.getName());
			return -1;
		}

		return dataTypeInstance.getLength();
	}

	PluginTool getPluginTool() {
		return tool;
	}

	/**
	 * Get rid of the dynamically created list of data types
	 */
	private void clearActions(List<DataAction> actions) {
		Iterator<DataAction> iter = actions.iterator();
		while (iter.hasNext()) {
			DockingAction action = iter.next();
			tool.removeAction(action);
			action.dispose();
		}
		actions.clear();
	}

	/**
	 * Add the cycle group actions
	 */
	private void addCycleGroupActions() {

		if (dtmService == null) {
			return;
		}

		for (CycleGroup group : CycleGroup.ALL_CYCLE_GROUPS) {
			CycleGroupAction action = new CycleGroupAction(group, this);
			action.setEnabled(false);

			tool.addAction(action);
		}
	}

	/**
	 * Update the Favorites actions for favorite data types.
	 */
	private void updateFavoriteActions() {

		if (dtmService == null) {
			return;
		}

		// Clear existing actions
		clearActions(favoriteActions);

		// Add Favorite data actions
		List<DataType> favoritesList = dtmService.getFavorites();
		for (DataType dataType : favoritesList) {
			// we have to exclude this here because we explicitly add pointer whether it is
			// a favorite or not.
			if (dataType.isEquivalent(POINTER_DATA_TYPE)) {
				continue;
			}
			DataAction action = new DataAction(dataType, this);
			tool.addAction(action);
			favoriteActions.add(action);
		}
	}

	void updateRecentlyUsed(DataType dt) {
		if (dtmService != null) {
			dtmService.setRecentlyUsed(dt);
		}
	}

	private boolean isSelectionJustSingleDataInstance(ProgramSelection selection, Data data) {
		if (selection != null && data != null) {
			AddressSet dataAS = new AddressSet(data.getAddress(), data.getMaxAddress());
			return dataAS.hasSameAddresses(selection);
		}
		return false;
	}

	private void dataSettingsCallback(ListingActionContext context) {

		DataSettingsDialog dialog;

		Data data = getDataUnit(context);
		ProgramSelection selection = context.getSelection();
		if (selection != null && !selection.isEmpty() &&
			!isSelectionJustSingleDataInstance(selection, data)) {
			try {
				dialog = new DataSettingsDialog(context.getProgram(), selection);
			}
			catch (CancelledException e) {
				return;
			}
			if (!dialog.hasSettings()) {
				Msg.showError(this, tool.getActiveWindow(), "No Settings Found",
					"Common data settings were not found across selection");
				return;
			}
		}
		else {
			// get the structure dt we are over
			if (data == null) {
				return;
			}
			dialog = new DataSettingsDialog(data);
		}
		tool.showDialog(dialog);
		dialog.dispose();
	}

	DataType getSelectedDataType(DataTypesActionContext context) {
		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length != 1) {
			return null;
		}
		DataTypeTreeNode node = (DataTypeTreeNode) selectionPaths[0].getLastPathComponent();
		if (!(node instanceof DataTypeNode)) {
			return null;
		}
		DataTypeNode dataTypeNode = (DataTypeNode) node;
		DataType dataType = dataTypeNode.getDataType();
		if (dataType.getDataTypeManager() instanceof DataTypeManagerDB) {
			return dataType;
		}
		return null;
	}

	protected void editDefaultDataTypeSettings(DataTypesActionContext context) {
		DataType dataType = getSelectedDataType(context);
		if (dataType == null) {
			return;
		}
		DataTypeManager dtm = dataType.getDataTypeManager();
		if (!(dtm instanceof DataTypeManagerDB)) {
			return;
		}

		SettingsDefinition[] settingsDefinitions = dataType.getSettingsDefinitions();
		if (!(dtm instanceof ProgramDataTypeManager)) {
			// Non-Program use limited to TypeDefSettingsDefinition only
			settingsDefinitions =
				SettingsDefinition.filterSettingsDefinitions(settingsDefinitions, def -> {
					return (def instanceof TypeDefSettingsDefinition);
				});
		}

		DataTypeSettingsDialog dialog = new DataTypeSettingsDialog(dataType, settingsDefinitions);
		tool.showDialog(dialog);
		dialog.dispose();
	}

	private void editDefaultComponentSettings(ComponentContext context) {
		DataTypeSettingsDialog dialog = new DataTypeSettingsDialog(context.getDataTypeComponent());
		tool.showDialog(dialog);
		dialog.dispose();
		dialog = null;
	}

	protected boolean isDefaultDataTypeSettingsAllowed(DataTypesActionContext context) {
		DataType dt = getSelectedDataType(context);
		if (dt == null) {
			return false;
		}

		DataTypeManager dtm = dt.getDataTypeManager();
		if (dtm instanceof BuiltInDataTypeManager) {
			return false; // no settings modifications are permitted
		}
		if ((dt instanceof BuiltIn) && !dtm.allowsDefaultBuiltInSettings()) {
			// prevent BuiltIn settings modification when not allowed
			return false;
		}

		SettingsDefinition[] settingsDefinitions = dt.getSettingsDefinitions();
		if (dtm instanceof ProgramBasedDataTypeManager) {
			// Any defined setting may be modified within a Program
			return settingsDefinitions.length != 0;
		}

		// Non-Program use limited to TypeDefSettingsDefinition modification only
		for (SettingsDefinition def : settingsDefinitions) {
			if (def instanceof TypeDefSettingsDefinition) {
				return true;
			}
		}
		return false;
	}

	boolean isDefaultComponentSettingsAllowed(ComponentContext context) {
		// Note: targetDtm should not be modified and reflects the ultimate target.
		// This context is intended to be used by composite editors where the component
		// parent datatype resides within a temporary datatype manager and not the targetDtm 
		// until a subsequent save/apply is performed when the settings will get copied.
		DataTypeManager targetDtm = context.getDataTypeManager();
		if (targetDtm.allowsDefaultComponentSettings()) {
			DataType dt = context.getDataTypeComponent().getDataType();
			return dt.getSettingsDefinitions().length != 0;
		}
		return false;
	}

	boolean isDataTypeSettingsAllowed(ListingActionContext context, boolean editDefaults) {
		ProgramSelection selection = context.getSelection();
		Data data = getDataUnit(context);
		if (selection != null && !selection.isEmpty() &&
			!isSelectionJustSingleDataInstance(selection, data)) {
			return !editDefaults;
		}
		if (data == null) {
			return false;
		}
		return data.getDataType().getSettingsDefinitions().length != 0;
	}

	private void editDefaultDataSettings(ListingActionContext context) {

		// get the structure dt we are over
		Data data = getDataUnit(context);
		if (data == null) {
			return;
		}

		DataTypeSettingsDialog dialog = null;
		Data parent = data.getParent();
		if (parent != null) {
			DataType parentDT = parent.getDataType();
			if (parentDT instanceof Composite) {
				int[] path = context.getLocation().getComponentPath();
				dialog = new DataTypeSettingsDialog(
					((Composite) parentDT).getComponent(path[path.length - 1]));
			}
		}
		if (dialog == null) {
			DataType dt = data.getDataType();
			dialog = new DataTypeSettingsDialog(dt, dt.getSettingsDefinitions());
		}

		tool.showDialog(dialog);
		dialog.dispose();
		dialog = null;
	}

	/**
	 * Callback for edit data type action
	 */
	private void editDataTypeCallback(ListingActionContext context) {
		Data data = getDataUnit(context);
		if (data == null) {
			return;
		}
		DataType dataType = data.getBaseDataType();
		if (dtmService.isEditable(dataType)) {
			dtmService.edit(dataType);
		}
		else {
			data = data.getParent();
			if (data != null) {
				dataType = data.getBaseDataType();
				if (dtmService.isEditable(dataType)) {
					dtmService.edit(dataType);
				}
			}
		}
	}

	@Override
	public void dispose() {
		favoritesUpdateManager.dispose();
		if (dtmService != null) {
			dtmService.removeDataTypeManagerChangeListener(adapter);
		}
		super.dispose();

		favoriteActions.clear();
		createStructureAction.dispose();
	}

	Data getDataUnit(ListingActionContext context) {
		ProgramLocation location = context.getLocation();
		ProgramSelection selection = context.getSelection();
		Program program = context.getProgram();

		if (!(location instanceof CodeUnitLocation)) {
			return null;
		}

		Address start = location.getAddress();
		if (selection != null && !selection.isEmpty()) {
			start = selection.getMinAddress();
			if (selection.getInteriorSelection() != null) {
				location = selection.getInteriorSelection().getFrom();
			}
		}

		return getDataUnit(program, start, location.getComponentPath());
	}

	static Data getDataUnit(Program program, Address start, int[] componentPath) {
		if (start == null) {
			return null;
		}
		Data data = program.getListing().getDataContaining(start);
		if (data == null) {
			return null;
		}
		if (data.getNumComponents() <= 0) {
			return data;
		}
		if (componentPath == null || componentPath.length <= 0) {
			return data;
		}
		Data compData = data.getComponent(componentPath);
		return (compData == null ? data : compData);
	}

	@Override
	public boolean isCreateDataAllowed(ListingActionContext context) {
		ProgramLocation location = context.getLocation();

		if (!(location instanceof CodeUnitLocation)) {
			return false;
		}

		Data data = getDataUnit(context);
		if (data == null) {
			return false;
		}
		Data pdata = data.getParent();
		if (pdata != null && pdata.isArray()) {
			return false;
		}
		return true;
	}

}

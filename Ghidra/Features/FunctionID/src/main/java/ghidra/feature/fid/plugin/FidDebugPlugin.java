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
package ghidra.feature.fid.plugin;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.debug.DbViewerProvider;
import ghidra.app.script.AskDialog;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.debug.FidSearchDebugDialog;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * The FID program plugin is actually ONLY needed for administrative actions in FID.
 * The FID function name search analyzer will occur in Ghidra with or without this
 * plugin enabled.  This plugin has many actions, such as creating, attaching, enabling,
 * populating, and debugging (searching) FID databases.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Function ID Debug",
	description = "This plugin is for debugging function identification libraries."
)
//@formatter:on
public class FidDebugPlugin extends ProgramPlugin implements ChangeListener {

	private static final String FUNCTION_ID_DEBUG_NAME = "Function ID Debug";
	private static final String MENU_GROUP_2 = "group2";

	private FidService service;
	private FidFileManager fidFileManager;
	private List<DockingAction> debugActions;

	private DockingAction createRawFileAction;

	public FidDebugPlugin(PluginTool tool) {
		super(tool, true, true);
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		SwingUtilities.invokeLater(() -> updateActions());
	}

	private void updateActions() {
		createDynamicDebugActions();
		enableActions();
	}

	@Override
	protected void init() {
		super.init();
		fidFileManager = FidFileManager.getInstance();
		fidFileManager.addChangeListener(this);
		service = new FidService();
		debugActions = new ArrayList<>();
		createDebugActions();
		createDynamicDebugActions();
		enableActions();
	}

	@Override
	protected void cleanup() {
		fidFileManager.removeChangeListener(this);
		super.dispose();
	}

	/**
	 * Method to create the "standard" actions, which users controlling or creating
	 * FID databases would want to use.
	 */
	private void createDebugActions() {
		if (tool == null) {
			throw new AssertException("Called create debug actions with tool null");
		}
		DockingAction action = new DockingAction("Launch Debug Search Window", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				try {
					FidSearchDebugDialog fidSearchDebugDialog = new FidSearchDebugDialog(service);
					tool.showDialog(fidSearchDebugDialog);
				}
				catch (VersionException | IOException e) {
					Msg.showError(this, null, "Can't open Fid Query Service", e);
				}
			}
		};
		action.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_TOOLS, FidPluginPackage.NAME, "Debug Search Window" },
			null, MENU_GROUP_2, MenuData.NO_MNEMONIC, "7"));
		action.setDescription("Open a window to search the FID DBs in debug mode");
		action.setHelpLocation(
			new HelpLocation(FidPlugin.FID_HELP, "FunctionIDDebug"));
		tool.addAction(action);

		action = new HashAction(this);
		action.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_TOOLS, FidPluginPackage.NAME,
				"Debug Search Window (Current Function)" },
			null, MENU_GROUP_2, MenuData.NO_MNEMONIC, "1"));
		action.setDescription("FidHashes the current function for debug purposes");
		action.setHelpLocation(
			new HelpLocation(FidPlugin.FID_HELP, "FunctionIDDebug"));
		tool.addAction(action);

		createRawFileAction = new DockingAction("raw file", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				createRawFile();
			}
		};
		createRawFileAction.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_TOOLS, FidPluginPackage.NAME,
				"Create Read-only Database" }, null, MENU_GROUP_2, MenuData.NO_MNEMONIC, "1"));
		createRawFileAction.setDescription(
			"Creates a raw read-only database suitable for distribution in the installation directory");
		createRawFileAction.setHelpLocation(
			new HelpLocation(FidPlugin.FID_HELP, "FunctionIDDebug"));

		tool.addAction(createRawFileAction);
	}

	/**
	 * Creates a raw read-only database file from a packed database.  This file is useful
	 * for including in a distribution.
	 */
	protected void createRawFile() {
		FidFile fidFile = askChoice("Choose destination FidDb",
			"Please choose the destination FidDb for population",
			fidFileManager.getUserAddedFiles(), null);
		if (fidFile == null) {
			return;
		}
		GhidraFileChooser chooser = new GhidraFileChooser(tool.getToolFrame());
		chooser.setTitle("Where do you want to create the read-only installable database?");
		chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
		File selectedFile = chooser.getSelectedFile();
		if (selectedFile == null) {
			return;
		}
		File outputFile =
			new File(selectedFile, fidFile.getBaseName() + FidFile.FID_RAW_DATABASE_FILE_EXTENSION);

		try (FidDB fidDB = fidFile.getFidDB(false)) {
			fidDB.saveRawDatabaseFile(outputFile, TaskMonitor.DUMMY);
		}
		catch (VersionException | IOException | CancelledException e) {
			// BTW CancelledException can't happen because we used a DUMMY monitor.
			Msg.showError(this, null, "Error saving read-only installable database", e.getMessage(),
				e);
		}
	}

	/**
	 * Method to create the "debug" actions for the FID administrator.  Right now that just means
	 * search and inspection type commands to display database contents.
	 */
	private void createDynamicDebugActions() {
		for (DockingAction action : debugActions) {
			PluginTool pluginTool = tool;
			if (pluginTool != null) {
				pluginTool.removeAction(action);
			}
		}
		debugActions.clear();

		List<FidFile> allFidFiles = fidFileManager.getFidFiles();

		for (final FidFile fidFile : allFidFiles) {
			final String actionName = "Table Viewer - " + fidFile.getName();
			DockingAction action = new DockingAction(actionName, getName()) {
				@Override
				public void actionPerformed(ActionContext context) {

					// Show existing provider if it exists
					List<FidDbViewerProvider> componentProviders =
						tool.getWindowManager().getComponentProviders(FidDbViewerProvider.class);
					for (ComponentProvider comp : componentProviders) {
						if (((FidDbViewerProvider) comp).fidDB.getPath().equals(
							fidFile.getPath())) {
							tool.getWindowManager().showComponent(comp, true);
							return;
						}
					}

					// Show new dbViewer provider for fidFile
					try {
						new FidDbViewerProvider(fidFile);
					}
					catch (VersionException | IOException e) {
						Msg.error(FidDebugPlugin.this, "Error opening Fid database", e);
					}
				}
			};
			action.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_TOOLS,
				FidPluginPackage.NAME, "Table Viewer", fidFile.getName() }, null, MENU_GROUP_2,
				MenuData.NO_MNEMONIC, "6"));
			action.setDescription(
				"Opens new DB Table Viewer to browse the database in " + fidFile.getName());
			action.setHelpLocation(
				new HelpLocation(FidPlugin.FID_HELP, "FunctionIDPlugin"));
			action.setEnabled(true);
			if (tool != null) {
				tool.addAction(action);
			}
			debugActions.add(action);
		}
		// make these appear at the bottom of the Fid Menu.
		tool.setMenuGroup(
			new String[] { ToolConstants.MENU_TOOLS, FidPluginPackage.NAME, "Table Viewer" },
			"zzz");

	}

	private class FidDbViewerProvider extends DbViewerProvider {
		private FidDB fidDB;

		FidDbViewerProvider(FidFile fidFile) throws VersionException, IOException {
			super(FidDebugPlugin.this);
			fidDB = fidFile.getFidDB(false);
			setTransient();
			setWindowGroup("FID DbViewer");
			setTitle("FID DbViewer: " + fidDB.getName());
			openDatabase(fidDB.getPath(), fidDB.getDBHandle());
			tool.addComponentProvider(this, true);
		}

		@Override
		public void closeComponent() {
			super.closeComponent();
			fidDB.close();
		}

	}

	/**
	 * Method to properly set action enablement based upon appropriate business logic.
	 */
	private void enableActions() {
		boolean atLeastOneUserFidDb = fidFileManager.getUserAddedFiles().size() > 0;
		createRawFileAction.setEnabled(atLeastOneUserFidDb);
	}

	/**
	 * Method to ask a user to select from an array of choices (copied from GhidraScript).
	 * @param title popup window title
	 * @param message message to display during choice
	 * @param choices array of choices for the users
	 * @param defaultValue the default value to select
	 * @return the user's choice, or null
	 * @throws CancelledException if the user cancels
	 */
	protected <T> T askChoice(String title, String message, List<T> choices, T defaultValue) {
		AskDialog<T> dialog =
			new AskDialog<>(null, title, message, AskDialog.STRING, choices, defaultValue);
		if (dialog.isCanceled()) {
			return null;
		}

		T s = dialog.getChoiceValue();
		return s;
	}

	/**
	 * Class that implements hashing the current function in the listing.
	 */
	class HashAction extends ListingContextAction {
		FidDebugPlugin plugin;

		public HashAction(FidDebugPlugin plugin) {
			super("FidDbHash Function", plugin.getName());
			this.plugin = plugin;
		}

		@Override
		public void actionPerformed(ListingActionContext context) {
			Address address = context.getAddress();
			Program program = context.getProgram();
			FunctionManager functionManager = program.getFunctionManager();
			Function function = functionManager.getFunctionContaining(address);
			if (function != null) {
				StringBuilder buffer = new StringBuilder();

				try {
					FidHashQuad hash = plugin.service.hashFunction(function);

					if (hash == null) {
						Msg.showError(this, null, "Function too small",
							"Please select a function with at least " +
								plugin.service.getShortHashCodeUnitLength() + " code units");
						return;
					}
					String fullHashSearch = String.format("0x%016x", hash.getFullHash());
					String specificHashSearch = String.format("0x%016x", hash.getSpecificHash());
					FidSearchDebugDialog fidSearchDebugDialog = new FidSearchDebugDialog(service);
					fidSearchDebugDialog.setFullHashText(fullHashSearch);
					fidSearchDebugDialog.setSpecificHashText(specificHashSearch);
					tool.showDialog(fidSearchDebugDialog);
				}
				catch (MemoryAccessException e) {
					buffer.append("MemoryAccessException during hash: " + e.getMessage());
				}
				catch (VersionException e) {
					buffer.append("VersionException during hash: " + e.getMessage());
				}
				catch (IOException e) {
					buffer.append("IOException during hash: " + e.getMessage());
				}
			}
		}

		@Override
		protected boolean isEnabledForContext(ListingActionContext context) {
			Address address = context.getAddress();
			if (context.hasSelection() || address == null) {
				return false;
			}
			return context.getProgram().getFunctionManager().getFunctionContaining(address) != null;
		}
	}
}

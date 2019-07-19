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
import java.util.List;

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.AskDialog;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;

/**
 * The FID program plugin is actually ONLY needed for administrative actions in FID.
 * The FID function name search analyzer will occur in Ghidra with or without this
 * plugin enabled.  This plugin has many actions, such as creating, attaching, enabling,
 * populating, and debugging (searching) FID databases.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = FidPluginPackage.NAME,
	category = PluginCategoryNames.SEARCH,
	shortDescription = FidPlugin.FUNCTION_ID_NAME,
	description = "This plugin is for creating and maintaining function identification libraries."
)
//@formatter:on
public class FidPlugin extends ProgramPlugin implements ChangeListener {
	private static final String MENU_GROUP_1 = "group1";

	static final String FUNCTION_ID_NAME = "Function ID";

	public static final String FID_HELP = "FunctionID";

	private FidService service;
	private FidFileManager fidFileManager;

	private DockingAction chooseAction;
	private DockingAction createAction;
	private DockingAction attachAction;
	private DockingAction detachAction;
	private DockingAction populateAction;

	public FidPlugin(PluginTool tool) {
		super(tool, true, true);
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		SwingUtilities.invokeLater(() -> updateActions());
	}

	private void updateActions() {
		enableActions();
	}

	@Override
	protected void init() {
		super.init();
		fidFileManager = FidFileManager.getInstance();
		fidFileManager.addChangeListener(this);
		service = new FidService();
		createStandardActions();
		enableActions();
	}

	@Override
	protected void cleanup() {
		fidFileManager.removeChangeListener(this);
		super.cleanup();
	}

	/**
	 * Method to create the "standard" actions, which users controlling or creating
	 * FID databases would want to use.
	 */
	private void createStandardActions() {
		DockingAction action;

		action = new DockingAction("Choose Active FidDbs", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				chooseActiveFidDbs();
			}
		};
		action.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_TOOLS, FidPluginPackage.NAME,
				"Choose active FidDbs..." }, null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "1"));
		action.setDescription("Select which FidDbs are used during Fid Search");
		action.setHelpLocation(new HelpLocation(FID_HELP, "chooseactivemenu"));
		tool.addAction(action);
		chooseAction = action;

		action = new DockingAction("Create new empty FidDb", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				createFidDb();
			}
		};
		action.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_TOOLS, FidPluginPackage.NAME,
				"Create new empty FidDb..." }, null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "2"));
		action.setDescription("Create a new, empty FidDb file in your file system");
		action.setHelpLocation(new HelpLocation(FID_HELP, "createemptyfid"));
		tool.addAction(action);
		createAction = action;

		action = new DockingAction("Attach existing FidDb", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				attachFidDb();
			}
		};
		action.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_TOOLS, FidPluginPackage.NAME,
				"Attach existing FidDb..." }, null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "3"));
		action.setDescription("Attach an existing FidDb file from your file system");
		action.setHelpLocation(new HelpLocation(FID_HELP, "attachfid"));
		tool.addAction(action);
		attachAction = action;

		action = new DockingAction("Detach attached FidDb", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				removeFidFile();
			}
		};
		action.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_TOOLS, FidPluginPackage.NAME,
				"Detach attached FidDb..." }, null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "4"));
		action.setDescription("Detach an already attached FidDb");
		action.setHelpLocation(new HelpLocation(FID_HELP, "detachfid"));
		tool.addAction(action);
		detachAction = action;

		action = new DockingAction("Populate FidDb from programs", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				PopulateFidDialog populateFidDialog = new PopulateFidDialog(tool, service);
				tool.showDialog(populateFidDialog);
			}
		};
		action.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_TOOLS, FidPluginPackage.NAME,
				"Populate FidDb from programs..." },
			null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "5"));
		action.setDescription("Populate an existing FidDb with all programs under a domain folder");
		action.setHelpLocation(new HelpLocation(FID_HELP, "populatedialog"));
		tool.addAction(action);
		populateAction = action;

	}

	/**
	 * Method to select which known FID databases are currently active
	 * during search.
	 */
	private synchronized void chooseActiveFidDbs() {
		ActiveFidConfigureDialog dialog =
			new ActiveFidConfigureDialog(fidFileManager.getFidFiles());
		tool.showDialog(dialog);
	}

	/**
	 * Method to create a new FID database. The user will be prompted to enter a file
	 * name for the new database.  They can enter the name with or without the required
	 * extension (.fidb).  If they don't, we will add it for them.
	 */
	private void createFidDb() {
		File dbFile = askFile("Create new FidDb file", "Create");
		if (dbFile == null) {
			return;
		}

		if (!dbFile.getName().endsWith(FidFile.FID_PACKED_DATABASE_FILE_EXTENSION)) {
			dbFile = new File(dbFile.getParentFile(),
				dbFile.getName() + FidFile.FID_PACKED_DATABASE_FILE_EXTENSION);
		}

		try {
			fidFileManager.createNewFidDatabase(dbFile);
		}
		catch (DuplicateFileException e) {
			Msg.showError(this, tool.getToolFrame(), "Error creating new FidDb file",
				"File already exists: " + dbFile.getAbsolutePath());
		}
		catch (IOException e) {
			Msg.showError(this, tool.getToolFrame(), "Error creating new FidDb file",
				"Caught IOException creating FidDb file", e);
		}
	}

	/**
	 * Method to attach an already-created (but heretofore unknown) database.
	 */
	private void attachFidDb() {
		File dbFile = askFile("Attach existing FidDb file", "Attach");
		if (dbFile != null) {
			fidFileManager.addUserFidFile(dbFile);
		}
	}

	/**
	 * Method to "forget" about (close and stop trying to re-open next session) a FID database.
	 */
	private void removeFidFile() {
		FidFile fidFile = askChoice("Choose FidDb to detach", "Please choose the FidDb to detach",
			fidFileManager.getUserAddedFiles(), null);
		if (fidFile != null) {
			fidFileManager.removeUserFile(fidFile);
		}
	}

	/**
	 * Method to properly set action enablement based upon appropriate business logic.
	 */
	private void enableActions() {
		boolean atLeastOneFidDb = fidFileManager.getFidFiles().size() > 0;
		boolean atLeastOneUserFidDb = fidFileManager.getUserAddedFiles().size() > 0;
		chooseAction.setEnabled(atLeastOneFidDb);
		createAction.setEnabled(true);
		attachAction.setEnabled(true);
		detachAction.setEnabled(atLeastOneUserFidDb);
		populateAction.setEnabled(atLeastOneUserFidDb);
	}

	/**
	 * Method to ask for a file (copied from GhidraScript).
	 * @param title popup window title
	 * @param approveButtonText text for the "yes" button
	 * @return the file chosen, or null
	 */
	private File askFile(final String title, final String approveButtonText) {
		final GhidraFileChooser chooser = new GhidraFileChooser(tool.getActiveWindow());
		chooser.setApproveButtonText(approveButtonText);
		chooser.setTitle(title);
		chooser.setFileSelectionMode(GhidraFileChooser.FILES_ONLY);
		return chooser.getSelectedFile();
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
	private <T> T askChoice(String title, String message, List<T> choices, T defaultValue) {
		AskDialog<T> dialog =
			new AskDialog<>(null, title, message, AskDialog.STRING, choices, defaultValue);
		if (dialog.isCanceled()) {
			return null;
		}

		T s = dialog.getChoiceValue();
		return s;
	}
}

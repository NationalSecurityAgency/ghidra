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

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.CorePluginPackage;
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
	packageName = CorePluginPackage.NAME,
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

	public FidPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		tool.contextChanged(null); // update fid action enablement
	}

	@Override
	protected void init() {
		super.init();
		fidFileManager = FidFileManager.getInstance();
		fidFileManager.addChangeListener(this);
		service = new FidService();
		createStandardActions();
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
		new ActionBuilder("Choose Active FidDbs", getName())
				.enabledWhen(ac -> fidFileManager.hasFidFiles())
				.onAction(ac -> chooseActiveFidDbs())
				.menuPath(ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Choose active FidDbs...")
				.menuGroup(MENU_GROUP_1, "1")
				.description("Select which FidDbs are used during Fid Search")
				.helpLocation(new HelpLocation(FID_HELP, "chooseactivemenu"))
				.buildAndInstall(tool);

		new ActionBuilder("Create new empty FidDb", getName())
				.enabledWhen(ac -> true)
				.onAction(ac -> createFidDb())
				.menuPath(ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Create new empty FidDb...")
				.menuGroup(MENU_GROUP_1, "2")
				.description("Create a new, empty FidDb file in your file system")
				.helpLocation(new HelpLocation(FID_HELP, "createemptyfid"))
				.buildAndInstall(tool);

		new ActionBuilder("Attach existing FidDb", getName())
				.enabledWhen(ac -> true)
				.onAction(ac -> attachFidDb())
				.menuPath(ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Attach existing FidDb...")
				.menuGroup(MENU_GROUP_1, "3")
				.description("Attach an existing FidDb file from your file system")
				.helpLocation(new HelpLocation(FID_HELP, "attachfid"))
				.buildAndInstall(tool);

		new ActionBuilder("Detach attached FidDb", getName())
				.enabledWhen(ac -> fidFileManager.hasUserFidFiles())
				.onAction(ac -> removeFidFile())
				.menuPath(ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, "Detach attached FidDb...")
				.menuGroup(MENU_GROUP_1, "4")
				.description("Detach an already attached FidDb")
				.helpLocation(new HelpLocation(FID_HELP, "detachfid"))
				.buildAndInstall(tool);

		new ActionBuilder("Populate FidDb from programs", getName())
				.enabledWhen(ac -> fidFileManager.hasUserFidFiles())
				.onAction(ac -> {
					PopulateFidDialog populateFidDialog = new PopulateFidDialog(tool, service);
					tool.showDialog(populateFidDialog);
				})
				.menuPath(ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME,
					"Populate FidDb from programs...")
				.menuGroup(MENU_GROUP_1, "5")
				.description("Populate an existing FidDb with all programs under a domain folder")
				.helpLocation(new HelpLocation(FID_HELP, "populatedialog"))
				.buildAndInstall(tool);
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
	 * Method to ask for a file (copied from GhidraScript).
	 * @param title popup window title
	 * @param approveButtonText text for the "yes" button
	 * @return the file chosen, or null
	 */
	private File askFile(final String title, final String approveButtonText) {
		final GhidraFileChooser chooser = new GhidraFileChooser(tool.getActiveWindow());
		chooser.setApproveButtonText(approveButtonText);
		chooser.setTitle(title);
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		File file = chooser.getSelectedFile();
		chooser.dispose();
		return file;
	}

	/**
	 * Method to ask a user to select from an array of choices (copied from GhidraScript).
	 * @param title popup window title
	 * @param message message to display during choice
	 * @param choices array of choices for the users
	 * @param defaultValue the default value to select
	 * @return the user's choice, or null
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

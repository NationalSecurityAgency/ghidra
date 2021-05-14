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
package pdb;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.SwingConstants;

import docking.DockingWindowManager;
import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.MultiLineMessageDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.PdbAnalyzerCommon;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import pdb.symbolserver.*;
import pdb.symbolserver.ui.ConfigPdbDialog;
import pdb.symbolserver.ui.LoadPdbDialog;
import pdb.symbolserver.ui.LoadPdbDialog.LoadPdbResults;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Import External PDB Files",
	description = "This plugin manages the import of PDB files to add debug information to a program."
)
//@formatter:on
public class PdbPlugin extends Plugin {
	private static final String PDB_SYMBOL_SERVER_OPTIONS = "PdbSymbolServer";
	private static final String SYMBOL_STORAGE_DIR_OPTION =
		PDB_SYMBOL_SERVER_OPTIONS + ".Symbol_Storage_Directory";
	private static final String SYMBOL_SEARCH_PATH_OPTION =
		PDB_SYMBOL_SERVER_OPTIONS + ".Symbol_Search_Path";

	// the name of the help directory under src/main/help/help/topics
	public static final String PDB_PLUGIN_HELP_TOPIC = "Pdb";

	public PdbPlugin(PluginTool tool) {
		super(tool);

		createActions();
	}

	private void createActions() {
		new ActionBuilder("Load PDB File", this.getName())
				.supportsDefaultToolContext(true)
				.withContext(ProgramActionContext.class)
				.validContextWhen(pac -> pac.getProgram() != null &&
					PdbAnalyzerCommon.canAnalyzeProgram(pac.getProgram()))
				.menuPath(ToolConstants.MENU_FILE, "Load PDB File...")
				.menuGroup("Import PDB", "3")
				.helpLocation(new HelpLocation(PDB_PLUGIN_HELP_TOPIC, "Load PDB File"))
				.onAction(pac -> loadPDB(pac))
				.buildAndInstall(tool);

		new ActionBuilder("Symbol Server Config", this.getName())
				.menuPath(ToolConstants.MENU_EDIT, "Symbol Server Config")
				.menuGroup(ToolConstants.TOOL_OPTIONS_MENU_GROUP)
				.helpLocation(new HelpLocation(PDB_PLUGIN_HELP_TOPIC, "Symbol Server Config"))
				.onAction(ac -> configPDB())
				.buildAndInstall(tool);
	}

	private void configPDB() {
		ConfigPdbDialog.showSymbolServerConfig();
	}

	private void loadPDB(ProgramActionContext pac) {
		Program program = pac.getProgram();
		AutoAnalysisManager currentAutoAnalysisManager =
			AutoAnalysisManager.getAnalysisManager(program);
		if (currentAutoAnalysisManager.isAnalyzing()) {
			Msg.showWarn(getClass(), null, "Load PDB",
				"Unable to load PDB file while analysis is running.");
			return;
		}

		boolean analyzed =
			program.getOptions(Program.PROGRAM_INFO).getBoolean(Program.ANALYZED, false);

		if (analyzed) {
			int response =
				OptionDialog.showOptionDialogWithCancelAsDefaultButton(null, "Load PDB Warning",
					"Loading PDB after running analysis may produce poor results." +
						"\nPDBs should generally be loaded prior to analysis or" +
						"\nautomatically during auto-analysis.",
					"Continue");
			if (response != OptionDialog.OPTION_ONE) {
				return;
			}
		}

		File pdbFile = null;
		try {
			LoadPdbResults loadPdbResults = LoadPdbDialog.choosePdbForProgram(program);
			if (loadPdbResults == null) {
				tool.setStatusInfo("Loading PDB was cancelled.");
				return;
			}
			pdbFile = loadPdbResults.pdbFile;

			tool.setStatusInfo("");

			DataTypeManagerService dataTypeManagerService =
				tool.getService(DataTypeManagerService.class);
			if (dataTypeManagerService == null) {
				Msg.showWarn(getClass(), null, "Load PDB",
					"Unable to locate DataTypeService in the current tool.");
				return;
			}

			// note: We intentionally use a 0-delay here.  Our underlying task may show modal
			//       dialog prompts.  We want the task progress dialog to be showing before any
			//       prompts appear.
			LoadPdbTask loadPdbTask = new LoadPdbTask(program, pdbFile,
				loadPdbResults.useMsDiaParser, loadPdbResults.control, dataTypeManagerService);
			TaskBuilder.withTask(loadPdbTask)
					.setStatusTextAlignment(SwingConstants.LEADING)
					.setLaunchDelay(0);
			new TaskLauncher(loadPdbTask, null, 0);

			// Check for error messages & exceptions and handle them here
			// (previously handled by the task, but dialog parenting issues in a modal
			// task cause timing issues)
			if (loadPdbTask.getResultException() != null) {
				throw loadPdbTask.getResultException();
			}
			else if (loadPdbTask.getResultMessages() != null) {
				MultiLineMessageDialog dialog = new MultiLineMessageDialog("Load PDB File",
					"There were warnings/errors loading PDB file: " + pdbFile,
					loadPdbTask.getResultMessages(),
					MultiLineMessageDialog.WARNING_MESSAGE, false);
				DockingWindowManager.showDialog(null, dialog);
			}
		}
		catch (Exception e) {
			String message = null;
			if (e instanceof InvocationTargetException && e.getCause() != null) {
				message =
					Objects.requireNonNullElse(e.getCause().getMessage(), e.getCause().toString());
			}
			else {
				message = Objects.requireNonNullElse(e.getMessage(), e.toString());
			}
			Msg.showError(this, null, "Error Loading PDB",
				"Error processing PDB file: " + pdbFile + "\n" + message, e);
		}
	}

	//-------------------------------------------------------------------------------------------------------

	/**
	 * Searches the currently configured symbol server paths for a Pdb symbol file.
	 * 
	 * @param program the program associated with the requested pdb file
	 * @param findOptions options that control how to search for the symbol file
	 * @param monitor a {@link TaskMonitor} that allows the user to cancel
	 * @return a File that points to the found Pdb symbol file, or null if no file was found
	 */
	public static File findPdb(Program program, Set<FindOption> findOptions, TaskMonitor monitor) {

		try {
			SymbolFileInfo symbolFileInfo = SymbolFileInfo.fromMetadata(program.getMetadata());
			if (symbolFileInfo == null) {
				return null;
			}
			// make a copy and add in the ONLY_FIRST_RESULT option
			findOptions = findOptions.isEmpty() ? EnumSet.noneOf(FindOption.class)
					: EnumSet.copyOf(findOptions);
			findOptions.add(FindOption.ONLY_FIRST_RESULT);

			SymbolServerInstanceCreatorContext temporarySymbolServerInstanceCreatorContext =
				SymbolServerInstanceCreatorRegistry.getInstance().getContext(program);

			SymbolServerService temporarySymbolServerService =
				getSymbolServerService(temporarySymbolServerInstanceCreatorContext);

			List<SymbolFileLocation> results =
				temporarySymbolServerService.find(symbolFileInfo, findOptions, monitor);
			if (!results.isEmpty()) {
				return temporarySymbolServerService.getSymbolFile(results.get(0), monitor);
			}
		}
		catch (CancelledException e) {
			// ignore
		}
		catch (IOException e) {
			Msg.error(PdbPlugin.class, "Error getting symbol file", e);
		}
		return null;
	}

	/**
	 * Returns a new instance of a {@link SymbolServerService} configured with values from the
	 * application's preferences, defaulting to a minimal instance if there is no config.
	 * 
	 * @param symbolServerInstanceCreatorContext an object that provides the necessary context to
	 * the SymbolServerInstanceCreatorRegistry to create the SymbolServers that are listed in the
	 * config values
	 * @return a new {@link SymbolServerService} instance, never null
	 */
	public static SymbolServerService getSymbolServerService(
			SymbolServerInstanceCreatorContext symbolServerInstanceCreatorContext) {
		SymbolServer temporarySymbolServer =
			symbolServerInstanceCreatorContext.getSymbolServerInstanceCreatorRegistry()
					.newSymbolServer(Preferences.getProperty(SYMBOL_STORAGE_DIR_OPTION, "", true),
						symbolServerInstanceCreatorContext);
		SymbolStore symbolStore =
			(temporarySymbolServer instanceof SymbolStore) ? (SymbolStore) temporarySymbolServer
					: new SameDirSymbolStore(symbolServerInstanceCreatorContext.getRootDir());
		List<SymbolServer> symbolServers =
			symbolServerInstanceCreatorContext.getSymbolServerInstanceCreatorRegistry()
					.createSymbolServersFromPathList(getSymbolSearchPaths(),
						symbolServerInstanceCreatorContext);
		return new SymbolServerService(symbolStore, symbolServers);
	}

	/**
	 * Persists the {@link SymbolStore} and {@link SymbolServer}s contained in the
	 * {@link SymbolServerService}.
	 * 
	 * @param symbolServerService {@link SymbolServerService} to save, or null if clear p
	 * reference values
	 */
	public static void saveSymbolServerServiceConfig(SymbolServerService symbolServerService) {
		if (symbolServerService != null) {
			Preferences.setProperty(SYMBOL_STORAGE_DIR_OPTION,
				symbolServerService.getSymbolStore().getName());

			String path = symbolServerService.getSymbolServers()
					.stream()
					.map(SymbolServer::getName)
					.collect(Collectors.joining(";"));
			Preferences.setProperty(SYMBOL_SEARCH_PATH_OPTION, path);
		}
		else {
			Preferences.setProperty(SYMBOL_STORAGE_DIR_OPTION, null);
			Preferences.setProperty(SYMBOL_SEARCH_PATH_OPTION, null);
		}
	}

	private static List<String> getSymbolSearchPaths() {
		String searchPathStr = Preferences.getProperty(SYMBOL_SEARCH_PATH_OPTION, "", true);

		String[] pathParts = searchPathStr.split(";");
		List<String> result = new ArrayList<>();
		for (String part : pathParts) {
			part = part.trim();
			if (!part.isEmpty()) {
				result.add(part);
			}
		}
		return result;
	}
}

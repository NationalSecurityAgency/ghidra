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

import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.bin.format.pdb.PdbParser;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorRestrictions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.TaskLauncher;

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

	private ProgramContextAction loadPdbAction;
	private GhidraFileChooser pdbChooser;

	public PdbPlugin(PluginTool tool) {
		super(tool);

		createActions();
	}

	private void createActions() {
		loadPdbAction = new ProgramContextAction("Load PDB File", this.getName()) {

			@Override
			public boolean isEnabledForContext(ProgramActionContext context) {
				return context.getProgram() != null;
			}

			@Override
			protected void actionPerformed(ProgramActionContext programContext) {
				loadPDB();
			}
		};

		MenuData menuData =
			new MenuData(new String[] { "&File", "Load PDB File..." }, null, "Import PDB");
		menuData.setMenuSubGroup("3"); // below the major actions in the "Import/Export" group
		loadPdbAction.setMenuBarData(menuData);

		loadPdbAction.setEnabled(false);
		loadPdbAction.setHelpLocation(new HelpLocation("ImporterPlugin", loadPdbAction.getName()));
		tool.addAction(loadPdbAction);
	}

	private void loadPDB() {
		Program program = GhidraProgramUtilities.getCurrentProgram(tool);
		AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(program);
		if (aam.isAnalyzing()) {
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

		try {
			File pdb = getPdbFile(program);
			if (pdb == null) {
				tool.setStatusInfo("Loading PDB was cancelled.");
				return;
			}

			boolean isPdbFile = pdb.getName().toLowerCase().endsWith(".pdb");

			AskPdbOptionsDialog optionsDialog = new AskPdbOptionsDialog(null, isPdbFile);
			if (optionsDialog.isCanceled()) {
				return;
			}

			boolean useMsDiaParser = optionsDialog.useMsDiaParser();
			PdbApplicatorRestrictions restrictions = optionsDialog.getApplicatorRestrictions();

			tool.setStatusInfo("");

			DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
			if (service == null) {
				Msg.showWarn(getClass(), null, "Load PDB",
					"Unable to locate DataTypeService in the current tool.");
				return;
			}

			// note: We intentionally use a 0-delay here.  Our underlying task may show modal
			//       dialog prompts.  We want the task progress dialog to be showing before any
			//       promts appear.
			LoadPdbTask task = new LoadPdbTask(program, pdb, useMsDiaParser, restrictions, service);
			new TaskLauncher(task, null, 0);
		}
		catch (Exception pe) {
			Msg.showError(getClass(), null, "Error Loading PDB", pe.getMessage(), pe);
		}
	}

	private File getPdbFile(Program program) {
		File pdbFile = PdbParser.findPDB(program);
		if (pdbChooser == null) {
			pdbChooser = new GhidraFileChooser(tool.getToolFrame());
			pdbChooser.setTitle("Select PDB file to load:");
			pdbChooser.setApproveButtonText("Select PDB");
			pdbChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			pdbChooser.setFileFilter(new ExtensionFileFilter(new String[] { "pdb", "xml" },
				"Program Database Files and PDB XML Representations"));
		}

		if (pdbFile != null) {
			pdbChooser.setSelectedFile(pdbFile);
		}

		File selectedFile = pdbChooser.getSelectedFile();
		return selectedFile;
	}
}

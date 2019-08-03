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
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.bin.format.pdb.PdbException;
import ghidra.app.util.bin.format.pdb.PdbParser;
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

		try {
			File pdb = getPdbFile(program);
			if (pdb == null) {
				tool.setStatusInfo("Loading PDB was cancelled.");
				return;
			}
			tool.setStatusInfo("");
			DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
			if (service == null) {
				Msg.showWarn(getClass(), null, "Load PDB",
					"Unable to locate DataTypeService in the current tool.");
				return;
			}

			TaskLauncher.launch(new LoadPdbTask(program, pdb, service));
		}
		catch (Exception pe) {
			Msg.showError(getClass(), null, "Error", pe.getMessage());
		}
	}

	private File getPdbFile(Program program) throws PdbException {
		File pdbFile = PdbParser.findPDB(program);
		if (pdbChooser == null) {
			pdbChooser = new GhidraFileChooser(tool.getToolFrame());
			pdbChooser.setTitle("Select PDB file to load:");
			pdbChooser.setApproveButtonText("Select PDB");
			pdbChooser.setFileSelectionMode(GhidraFileChooser.FILES_ONLY);
			pdbChooser.setFileFilter(new ExtensionFileFilter(new String[] { "pdb", "xml" },
				"Program Database Files and PDB XML Representations"));
		}

		pdbChooser.setSelectedFile(pdbFile);

		File selectedFile = pdbChooser.getSelectedFile();
		return selectedFile;
	}
}

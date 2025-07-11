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
package ghidra.app.plugin.core.exporter;

import java.awt.event.KeyEvent;
import java.util.List;

import docking.action.*;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.main.FrontEndService;
import ghidra.framework.main.datatable.FrontendProjectTreeAction;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Export Program/Datatype Archives",
	description = "This plugin exports a program or datatype archive to an external file."
)
//@formatter:on
public class ExporterPlugin extends Plugin implements ApplicationLevelPlugin {

	private FrontEndService frontEndService;

	public ExporterPlugin(PluginTool tool) {
		super(tool);

		frontEndService = tool.getService(FrontEndService.class);

		createFrontEndAction();
		createToolAction();
	}

	private void createToolAction() {

		if (frontEndService != null) {
			return; // do not add File menu Export Program action to front-end
		}

		DockingAction action = new NavigatableContextAction("Export Program", getName()) {

			@Override
			protected void actionPerformed(NavigatableActionContext context) {
				Program program = context.getProgram();
				DomainFile domainFile = program.getDomainFile();
				ExporterDialog.showExporterDialog(tool, domainFile, program,
					context.getSelection());
			}
		};
		MenuData menuData =
			new MenuData(new String[] { "&File", "Export Program..." }, "Import Export");
		menuData.setMenuSubGroup("z"); // last in the "Save" group
		action.setMenuBarData(menuData);
		action.setKeyBindingData(new KeyBindingData(KeyEvent.VK_O, 0));
		action.setHelpLocation(new HelpLocation("ExporterPlugin", "Export"));
		action.setDescription(getPluginDescription().getDescription());
		tool.addAction(action);
	}

	protected ProgramSelection getSelection() {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		if (service != null) {
			return service.getCurrentSelection();
		}
		return null;
	}

	private void createFrontEndAction() {

		if (frontEndService == null) {
			return; // only add project tree actions to front-end
		}

		DockingAction action = new FrontendProjectTreeAction("Export", getName()) {

			@Override
			protected void actionPerformed(ProjectDataContext context) {
				DomainFile domainFile = context.getSelectedFiles().get(0);
				ExporterDialog.show(tool, domainFile);
			}

			@Override
			protected boolean isEnabledForContext(ProjectDataContext context) {
				List<DomainFolder> selectedFolders = context.getSelectedFolders();
				if (!selectedFolders.isEmpty()) {
					return false;
				}
				List<DomainFile> selectedFiles = context.getSelectedFiles();
				if (selectedFiles.size() != 1) {
					return false;
				}
				DomainFile domainFile = context.getSelectedFiles().get(0);
				if (domainFile.isLink() && domainFile.getLinkInfo().isFolderLink()) {
					return false;
				}
				return true;
			}
		};
		action.setPopupMenuData(new MenuData(new String[] { "Export..." }, "Export"));
		action.setDescription(getPluginDescription().getDescription());
		action.setHelpLocation(new HelpLocation("ExporterPlugin", "Export"));
		tool.addAction(action);
	}

}

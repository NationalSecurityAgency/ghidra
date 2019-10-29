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
package ghidra.feature.vt.gui.actions;

import static ghidra.feature.vt.gui.plugin.VTPlugin.VT_MAIN_MENU_GROUP;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.task.SaveTask;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskLauncher;
import resources.ResourceManager;

public class SaveVersionTrackingSessionAction extends DockingAction {

	static final Icon ICON = ResourceManager.loadImage("images/disk.png");

	private final VTController controller;

	public SaveVersionTrackingSessionAction(VTController controller) {
		super("Save", VTPlugin.OWNER);
		this.controller = controller;

		setToolBarData(new ToolBarData(ICON, VT_MAIN_MENU_GROUP));
		setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_FILE, "Save Session" }, ICON, "AAC"));
		setDescription("Save Version Tracking Changes");
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Version_Tracking_Tool"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		VTSession session = controller.getSession();
		if (session == null) {
			return;
		}

		if (session instanceof VTSessionDB) {
			VTSessionDB sessionDB = (VTSessionDB) session;
			DomainFile vtDomainFile = sessionDB.getDomainFile();

			// Save version tracking session changes.
			SaveTask saveVersionTrackingTask = new SaveTask(vtDomainFile);
			TaskLauncher.launch(saveVersionTrackingTask);
			Program program = controller.getDestinationProgram();
			DomainFile destinationProgramFile = program.getDomainFile();
			if (destinationProgramFile.isChanged()) {
				SaveTask saveDestinationTask = new SaveTask(destinationProgramFile);
				TaskLauncher.launch(saveDestinationTask);
			}

			controller.refresh();
		}
	}

	private boolean hasUnsavedVersionTrackingChanges() {
		// Check to see if there are unsaved changes to the results.
		VTSession session = controller.getSession();
		if (session == null) {
			return false;
		}
		if (session instanceof VTSessionDB) {
			VTSessionDB sessionDB = (VTSessionDB) session;
			if (sessionDB.isChanged()) {
				return true;
			}
		}
		Program destinationProgram = controller.getDestinationProgram();
		return destinationProgram.isChanged();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return hasUnsavedVersionTrackingChanges();
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}

}

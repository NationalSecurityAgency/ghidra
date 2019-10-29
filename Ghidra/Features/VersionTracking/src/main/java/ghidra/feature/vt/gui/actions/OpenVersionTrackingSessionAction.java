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

import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFileFilter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;

public class OpenVersionTrackingSessionAction extends DockingAction {

	private final VTController controller;

	public OpenVersionTrackingSessionAction(VTController controller) {
		super("Open Session", VTPlugin.OWNER);
		this.controller = controller;
		String[] menuPath = { ToolConstants.MENU_FILE, "Open Session..." };
		setMenuBarData(new MenuData(menuPath, "AAA"));
		setDescription("Opens a Version Tracking Session");
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Open_Session"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		PluginTool tool = controller.getTool();
		DataTreeDialog dialog =
			new DataTreeDialog(tool.getToolFrame(), "Open Version Tracking Session",
				DataTreeDialog.OPEN, new VTDomainFileFilter());

		tool.showDialog(dialog);
		if (!dialog.wasCancelled()) {
			DomainFile domainFile = dialog.getDomainFile();
			controller.openVersionTrackingSession(domainFile);
		}
	}

	class VTDomainFileFilter implements DomainFileFilter {
		public boolean accept(DomainFile f) {
			Class<?> c = f.getDomainObjectClass();
			return VTSession.class.isAssignableFrom(c);
		}
	}
}

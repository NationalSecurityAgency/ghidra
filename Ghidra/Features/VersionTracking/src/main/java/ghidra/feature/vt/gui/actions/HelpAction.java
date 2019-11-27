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

import java.net.URL;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import docking.help.Help;
import docking.help.HelpService;
import docking.tool.ToolConstants;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.ResourceManager;

public class HelpAction extends DockingAction {

	private static Icon ICON = ResourceManager.loadImage("images/help-browser.png");

	public HelpAction() {
		super("Version Tracking Help Action", VTPlugin.OWNER);

		String[] menuPath = { ToolConstants.MENU_HELP, "Workflow" };
		setMenuBarData(new MenuData(menuPath, ICON, "AAAHelpContents"));
		setToolBarData(new ToolBarData(ICON, "ZZZ"));
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Version_Tracking_Tool"));
	}

	@Override
	public void actionPerformed(ActionContext context) {

		HelpService help = Help.getHelpService();
		if (help == null) {
			Msg.showError(this, null, "Help Not Found",
				"HelpManager failed to initialize properly");
			return;
		}

		URL url =
			ResourceManager.getResource("help/topics/VersionTrackingPlugin/VT_Workflow.html");
		if (url == null) {
			Msg.showError(this, null, "Help Not Found",
				"Unable to find the Version Tracking workflow help");
			return;
		}

		help.showHelp(url);
	}

}

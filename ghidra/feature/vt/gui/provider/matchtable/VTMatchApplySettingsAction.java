/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.provider.matchtable;

import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.util.HelpLocation;

import javax.swing.Icon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;

public class VTMatchApplySettingsAction extends DockingAction {
	public static final String VERSION_TRACKING_OPTIONS_NAME = "Version Tracking";
	public static final String VERSION_TRACKING_APPLY_MARKUP_OPTIONS = "Apply Markup Options";

	static final Icon ICON = ResourceManager.loadImage("images/settings16.gif");
	private static final String MENU_GROUP = VTPlugin.VT_SETTINGS_MENU_GROUP;
	private static final String TITLE = "Version Tracking Options";

	private final VTController controller;

	public VTMatchApplySettingsAction(VTController controller) {
		super(TITLE, VTPlugin.OWNER);
		this.controller = controller;

		setToolBarData(new ToolBarData(ICON, MENU_GROUP));
		setPopupMenuData(new MenuData(new String[] { "Options..." }, ICON, MENU_GROUP));
		setDescription("Adjust the Apply Mark-up Settings for Applying Matches");
		setEnabled(true);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Match_Table_Settings"));

	}

	@Override
	public void actionPerformed(ActionContext context) {
		PluginTool tool = controller.getTool();
		OptionsService service = tool.getService(OptionsService.class);
		service.showOptionsDialog(VERSION_TRACKING_OPTIONS_NAME + "." +
//				VERSION_TRACKING_APPLY_MARKUP_OPTIONS, "Version Tracking");
			VERSION_TRACKING_APPLY_MARKUP_OPTIONS, "Apply");
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}
}

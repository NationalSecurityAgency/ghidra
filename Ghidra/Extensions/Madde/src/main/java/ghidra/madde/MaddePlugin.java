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
package ghidra.madde;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = MaddePluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Madde starter plugin",
	description = "A minimal plugin template for a Ghidra-based reverse engineering workflow."
)
public class MaddePlugin extends Plugin {

	private final DockingAction launchAction;
	private final DockingAction statusAction;

	public MaddePlugin(PluginTool tool) {
		super(tool);

		launchAction = new DockingAction("Madde: Open Workspace", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.info(this, "Madde starter plugin loaded.");
				Msg.info(this, "This is the legal Ghidra extension template for custom analysis flows.");
			}
		};
		launchAction.setEnabled(true);
		launchAction.setMenuBarData(new MenuData(new String[] { "Window", "Madde", "Open Workspace" }, "madde"));
		tool.addAction(launchAction);

		statusAction = new DockingAction("Madde: Status", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.info(this, "Madde status: ready");
			}
		};
		statusAction.setEnabled(true);
		statusAction.setMenuBarData(new MenuData(new String[] { "Window", "Madde", "Status" }, "maddeStatus"));
		tool.addAction(statusAction);
	}
}

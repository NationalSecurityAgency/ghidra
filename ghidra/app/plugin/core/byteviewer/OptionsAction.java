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
package ghidra.app.plugin.core.byteviewer;

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import resources.ResourceManager;

class OptionsAction extends DockingAction {
	public static final ImageIcon OPTIONS_ICON = ResourceManager.loadImage("images/wrench.png");

	private final ByteViewerComponentProvider provider;

	private final PluginTool tool;

	public OptionsAction(ByteViewerComponentProvider provider, Plugin plugin) {
		super("Byte Viewer Options", plugin.getName());
		this.provider = provider;
		this.tool = plugin.getTool();
		setEnabled(false);
		setDescription("Set Byte Viewer Options");
		setToolBarData(new ToolBarData(OPTIONS_ICON, "ZSettings"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		tool.showDialog(new ByteViewerOptionsDialog(provider), provider);
	}
}

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
package ghidra.app.plugin.core.debug.gui.memview;

import javax.swing.Icon;

import docking.action.builder.ToggleActionBuilder;
import generic.theme.GIcon;
import ghidra.app.plugin.core.bento.BentoProvider;
import ghidra.app.plugin.core.bento.BentoServicePlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class MemviewProvider extends BentoProvider {

	private static final Icon ICON_SYNC =
		ResourceManager.getScaledIcon(new GIcon("icon.widget.imagepanel.reset"), 12, 12);

	public MemviewProvider(PluginTool tool, BentoServicePlugin plugin) {
		super(tool, plugin, false);
	}

	@Override
	protected void createActions() {
		super.createActions();

		new ToggleActionBuilder("Toggle Tracking", getOwner()) //
				//.menuPath("&Toggle layout") //
				.toolBarIcon(ICON_SYNC)
				.helpLocation(new HelpLocation(getOwner(), "toggle_tracking")) //
				.onAction(ctx -> performToggleTracking(ctx))
				.selected(false)
				.buildAndInstallLocal(this);

	}
}

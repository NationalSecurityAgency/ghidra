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
package ghidra.app.plugin.core.debug.gui.memview.actions;

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.debug.gui.memview.MemviewProvider;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class ZoomOutAAction extends DockingAction {

	private final ImageIcon ICON = ResourceManager.loadImage("images/zoom_out.png");

	private MemviewProvider provider;

	public ZoomOutAAction(MemviewProvider provider) {
		super("Zoom Out (Addrs)", provider.getName());
		this.provider = provider;
		setEnabled(true);

		this.setToolBarData(new ToolBarData(ICON, "aoverview"));

		setDescription("Zoom Out (A)");
		setHelpLocation(new HelpLocation("DebuggerMemviewPlugin", "zoom"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		provider.changeZoomA(-1);
		provider.refresh();
	}

}

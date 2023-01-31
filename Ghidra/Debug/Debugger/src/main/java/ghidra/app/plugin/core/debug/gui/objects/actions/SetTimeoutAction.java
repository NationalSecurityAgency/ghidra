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
package ghidra.app.plugin.core.debug.gui.objects.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.script.AskDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

public class SetTimeoutAction extends DockingAction {

	DebuggerObjectsProvider provider;
	int timeout = 0;

	public SetTimeoutAction(PluginTool tool, String owner, DebuggerObjectsProvider provider) {
		super("SetTimeout", owner);
		setMenuBarData(
			new MenuData(new String[] { "Maintenance", "&Set Node Timeout" }, null, "M100"));
		setHelpLocation(new HelpLocation(owner, "set_node_timeout"));
		this.provider = provider;
		provider.addLocalAction(this);
		this.timeout = provider.getNodeTimeout();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		AskDialog<String> dialog =
			new AskDialog<String>("Set Node Timeout", "Seconds", AskDialog.INT, timeout);
		if (dialog.isCanceled()) {
			return;
		}
		timeout = Integer.parseInt(dialog.getValueAsString());
		provider.setNodeTimeout(timeout);
	}

	public void setNodeTimeout(int timeout) {
		this.timeout = timeout;
	}

}

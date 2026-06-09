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
package ghidra.app.plugin.core.debug.gui;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.plugin.core.debug.gui.control.TargetActionTask;
import ghidra.debug.api.target.Target.ActionEntry;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;

public class InvokeActionEntryAction extends DockingAction {
	protected final PluginTool tool;
	protected final ActionEntry entry;

	public InvokeActionEntryAction(Plugin plugin, ActionEntry entry) {
		super(entry.display(), plugin.getName());
		this.tool = plugin.getTool();
		this.entry = entry;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		TargetActionTask.runAction(tool, entry.display(), entry);
	}
}

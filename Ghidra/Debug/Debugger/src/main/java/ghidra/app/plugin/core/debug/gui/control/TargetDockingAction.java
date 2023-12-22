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
package ghidra.app.plugin.core.debug.gui.control;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingType;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.Target.ActionEntry;

class TargetDockingAction extends DockingAction {
	private final DebuggerControlPlugin plugin;
	private final ActionName action;
	private final String defaultDescription;

	private ActionEntry entry;

	public TargetDockingAction(String name, String owner, KeyBindingType keyBindingType,
			DebuggerControlPlugin plugin, ActionName action, String defaultDescription) {
		super(name, owner, keyBindingType);
		this.plugin = plugin;
		this.action = action;
		this.defaultDescription = defaultDescription;
	}

	private ActionEntry findEntry(ActionContext context) {
		Target target = plugin.current.getTarget();
		if (target == null) {
			return null;
		}
		for (ActionEntry ent : target.collectActions(action, context).values()) {
			if (ent.requiresPrompt()) {
				continue;
			}
			return ent;
			// TODO: What if multiple match? Do I care to display the extras?
		}
		return null;
	}

	protected void updateFromContext(ActionContext context) {
		entry = findEntry(context);
		if (entry == null) {
			setDescription(defaultDescription);
		}
		else {
			setDescription(entry.details());
		}
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		updateFromContext(context);
		return entry != null && entry.isEnabled();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (entry == null) {
			return;
		}
		plugin.runTask(getName(), entry);
	}
}

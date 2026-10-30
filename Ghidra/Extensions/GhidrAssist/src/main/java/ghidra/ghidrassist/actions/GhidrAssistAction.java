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
package ghidra.ghidrassist.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.ghidrassist.GhidrAssistPlugin;

/**
 * Base class for GhidrAssist right-click actions. Handles menu placement and
 * enablement; subclasses implement {@link #actionPerformed(ActionContext)}.
 */
abstract class GhidrAssistAction extends DockingAction {

	protected final GhidrAssistPlugin plugin;

	protected GhidrAssistAction(GhidrAssistPlugin plugin, String name, String menuEntry) {
		super(name, plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(
			new MenuData(new String[] { "GhidrAssist", menuEntry }, null, "GhidrAssist"));
		setHelpLocation(new ghidra.util.HelpLocation("GhidrAssist", "Actions"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return ActionSupport.contextIsSupported(context) &&
			ActionSupport.functionOf(context) != null;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return ActionSupport.contextIsSupported(context);
	}
}

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
package ghidra.app.plugin.core.decompile.actions;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.actions.AbstractFindReferencesToAddressAction;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
 * An action to show all references to the given address
 */
public class FindReferencesToAddressAction extends AbstractFindReferencesToAddressAction {

	public FindReferencesToAddressAction(PluginTool tool, String owner) {
		super(tool, owner);

		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionShowReferences"));
		setPopupMenuData(new MenuData(new String[] { LocationReferencesService.MENU_GROUP, NAME }));
	}

	@Override
	protected ProgramLocation getLocation(NavigatableActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return null;
		}
		return context.getLocation();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
		return decompilerContext.checkActionEnablement(() -> {
			return super.isEnabledForContext(context);
		});
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
		decompilerContext.performAction(() -> {
			super.actionPerformed(context);
		});
	}
}

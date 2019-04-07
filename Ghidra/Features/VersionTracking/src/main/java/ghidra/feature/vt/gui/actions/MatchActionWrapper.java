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
package ghidra.feature.vt.gui.actions;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchContext;
import ghidra.util.HelpLocation;

public class MatchActionWrapper extends DockingAction {

	private final VTPlugin plugin;
	private final DockingAction wrappedAction;
	private SubToolContext subToolContext;
	private ActionContext wrappedContext;

	public MatchActionWrapper(VTPlugin plugin, DockingAction action) {
		super("Wrapped Match Action: " + action.getName(), VTPlugin.OWNER);
		this.plugin = plugin;
		this.wrappedAction = action;

		// put this action in the menu in the same fashion as the wrapped action
		Icon icon = null;
		String menuGroup = null;
		MenuData popupMenuData = wrappedAction.getPopupMenuData();
		if (popupMenuData != null) {
			icon = popupMenuData.getMenuIcon();
			menuGroup = popupMenuData.getMenuGroup();
		}

		setPopupMenuData(new MenuData(
			new String[] { VTPlugin.MATCH_POPUP_MENU_NAME, action.getName() }, icon, menuGroup));

		HelpLocation helpLocation = DockingWindowManager.getHelpService().getHelpLocation(action);
		if (helpLocation != null) {
			setHelpLocation(helpLocation);
		}
	}

	@Override
	public void actionPerformed(ActionContext context) {
		VTController controller = plugin.getController();

		if (wrappedAction.isEnabledForContext(wrappedContext)) {
			wrappedAction.actionPerformed(wrappedContext);
		}

		VTMatch match = subToolContext.getMatch();
		controller.setSelectedMatch(match);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof CodeViewerActionContext)) {
			return false;
		}

		wrappedContext = createActionContext(context);
		if (wrappedContext == null) {
			return false;
		}
		return wrappedAction.isEnabledForContext(wrappedContext);
	}

	public ActionContext createActionContext(ActionContext originalContext) {
		// reset the context--this method is called before isEnabledForContext() and actionPerformed()
		getSubToolContext();

		VTController controller = plugin.getController();
		List<VTMatch> list = new ArrayList<>();
		VTMatch match = subToolContext.getMatch();
		if (match == null) {
			return null;
		}

		list.add(match);
		return new VTMatchContext(plugin.getMatchesProvider(), list, controller.getSession());
	}

	public SubToolContext getSubToolContext() {
		subToolContext = new SubToolContext(plugin);
		return subToolContext;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof CodeViewerActionContext)) {
			return false;
		}

		wrappedContext = createActionContext(context);
		VTMatch match = subToolContext.getMatch();
		return match != null;
	}
}

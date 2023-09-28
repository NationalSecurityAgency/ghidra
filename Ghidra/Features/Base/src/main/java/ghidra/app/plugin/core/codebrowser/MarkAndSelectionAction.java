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
package ghidra.app.plugin.core.codebrowser;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import generic.theme.GIcon;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.nav.Navigatable;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

/**
 * Actions for creating a selection using two distinct steps. The first time the action
 * is invoked, it records the current location as the start of a selection. The second time the
 * action is invoked it creates a selection from the recorded location to the current location. 
 */
public class MarkAndSelectionAction extends ToggleDockingAction {
	private Navigatable markedNavigatable;
	private ProgramLocation markedLocation;
	private Icon unarmedIcon;
	private Icon armedIcon;

	public MarkAndSelectionAction(String owner, String group, String subGroup) {
		super("Mark and Select", owner);
		buildIcons();
		MenuData menuData =
			new MenuData(new String[] { ToolConstants.MENU_SELECTION, "Mark Selection Start" });
		menuData.setMenuGroup(group);
		menuData.setMenuSubGroup(subGroup);
		setMenuBarData(menuData);
		setKeyBindingData(new KeyBindingData("m"));
		setToolBarData(
			new ToolBarData(unarmedIcon, ToolConstants.TOOLBAR_GROUP_THREE, "Z"));

		setHelpLocation((new HelpLocation(HelpTopics.SELECTION, "Mark_And_Select")));
		setContextClass(NavigatableActionContext.class, true);
		addToWindowWhen(NavigatableActionContext.class);

	}

	private void buildIcons() {
		unarmedIcon = new GIcon("icon.plugin.codebrowser.mark.and.select.unarmed");
		armedIcon = new GIcon("icon.plugin.codebrowser.mark.and.select.armed");
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (context instanceof NavigatableActionContext) {
			return ((NavigatableActionContext) context).getLocation() != null;
		}
		return false;
	}

	@Override
	public final boolean isValidContext(ActionContext context) {
		return context instanceof NavigatableActionContext;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (context instanceof NavigatableActionContext) {
			actionPerformed((NavigatableActionContext) context);
		}
	}

	protected void actionPerformed(NavigatableActionContext context) {
		Navigatable navigatable = context.getNavigatable();
		if (isArmed(navigatable)) {
			createSelection(navigatable);
		}
		else {
			armSelection(navigatable);
		}

		updateAction();
	}

	private void updateAction() {
		String menuName = "Mark Selection Start";
		String description = "Mark current location for selection start";
		Icon icon = unarmedIcon;

		if (markedLocation != null) {
			Address address = markedLocation.getByteAddress();
			menuName = "Create Selection from " + address;
			description = "Create seletion from marked location: " + address;
			icon = armedIcon;
		}

		MenuData menuBarData = getMenuBarData();
		menuBarData.setMenuItemName(menuName);
		setDescription(description);
		getToolBarData().setIcon(icon);

	}

	private void armSelection(Navigatable navigatable) {
		markedNavigatable = navigatable;
		markedLocation = navigatable.getLocation();
		if (markedLocation == null) {
			markedNavigatable = null;
		}
	}

	private void createSelection(Navigatable navigatable) {
		ProgramLocation location = navigatable.getLocation();
		Address start = markedLocation.getByteAddress();
		Address end = location.getByteAddress();
		ProgramSelection selection = new ProgramSelection(start, end);
		navigatable.setSelection(selection);

		// set back to unarmed
		markedLocation = null;
		markedNavigatable = null;
	}

	private boolean isArmed(Navigatable navigatable) {
		if (markedNavigatable == null || markedLocation == null) {
			return false;
		}
		if (navigatable != markedNavigatable) {
			return false;
		}
		if (markedLocation.getProgram() != navigatable.getProgram()) {
			return false;
		}
		return true;
	}

}

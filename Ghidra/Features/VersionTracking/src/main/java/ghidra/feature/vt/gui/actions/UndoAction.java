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

import java.awt.event.InputEvent;
import java.io.IOException;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.util.*;
import resources.ResourceManager;

public class UndoAction extends DockingAction {
	private final VTController controller;

	public UndoAction(VTController controller) {
		super("Undo", VTPlugin.OWNER);
		this.controller = controller;
		setHelpLocation(new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Undo"));
		String[] menuPath = { ToolConstants.MENU_EDIT, "&Undo" };
		String group = "ZZUndo";
		Icon icon = ResourceManager.loadImage("images/undo.png");
		MenuData menuData = new MenuData(menuPath, icon, group);
		menuData.setMenuSubGroup("1Undo"); // make this appear above the redo menu item
		setMenuBarData(menuData);
		setToolBarData(new ToolBarData(icon, group));
		setDescription("Undo");
		setKeyBindingData(new KeyBindingData('Z', InputEvent.CTRL_MASK));
	}

	@Override
	public void actionPerformed(ActionContext programContext) {
		VTSessionDB session = (VTSessionDB) controller.getSession();
		if (session == null) {
			return;
		}
		try {
			session.undo();
		}
		catch (IOException e) {
			Msg.showError(this, null, null, null, e);
		}
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		VTSessionDB session = (VTSessionDB) controller.getSession();
		if (session != null) {
			if (session.canUndo()) {
				String name = session.getName();
				getMenuBarData().setMenuItemName("Undo " + name);
				String tip = HTMLUtilities.toWrappedHTML("Undo " + session.getUndoName());
				setDescription(tip);
				return true;
			}
		}
		setDescription("Undo");
		getMenuBarData().setMenuItemName("Undo");
		return false;
	}

}

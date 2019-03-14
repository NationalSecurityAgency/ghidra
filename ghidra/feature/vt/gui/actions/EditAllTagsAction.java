/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.feature.vt.gui.editors.TagEditorDialog;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchContext;
import ghidra.util.HelpLocation;

import javax.swing.Icon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;

public class EditAllTagsAction extends DockingAction {

	private static final String MENU_GROUP = VTPlugin.TAG_MENU_GROUP;
	private static final Icon EDIT_TAG_ICON = ResourceManager.loadImage("images/tag_blue_edit.png");
	private static final String ACTION_NAME = "Edit VTMatch Tags";

	private final VTController controller;

	public EditAllTagsAction(VTController controller) {
		super(ACTION_NAME, VTPlugin.OWNER);
		this.controller = controller;

		setDescription("Edit Match Tags");
		setToolBarData(new ToolBarData(EDIT_TAG_ICON, MENU_GROUP));
		MenuData menuData = new MenuData(new String[] { "Edit Tags" }, EDIT_TAG_ICON, MENU_GROUP);
		menuData.setMenuSubGroup("3"); // after the Remove... action
		setPopupMenuData(menuData);
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Edit_Tag"));

	}

	@Override
	public void actionPerformed(ActionContext context) {
		editTag();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof VTMatchContext)) {
			return false;
		}

		VTMatchContext matchContext = (VTMatchContext) context;
		return matchContext.getSession() != null;
	}

	private void editTag() {
		TagEditorDialog dialog = new TagEditorDialog(controller.getSession());
		controller.getTool().showDialog(dialog, controller.getParentComponent());
	}

}

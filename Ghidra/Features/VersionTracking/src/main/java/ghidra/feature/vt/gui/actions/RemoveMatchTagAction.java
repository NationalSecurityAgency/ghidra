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

import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchTag;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchContext;
import ghidra.feature.vt.gui.task.ClearMatchTagTask;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskLauncher;

import java.util.List;

import javax.swing.Icon;
import javax.swing.JComponent;

import resources.ResourceManager;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.*;
import docking.widgets.OptionDialog;

public class RemoveMatchTagAction extends DockingAction {

	private static final String MENU_GROUP = VTPlugin.TAG_MENU_GROUP;
	private static final Icon EDIT_TAG_ICON =
		ResourceManager.loadImage("images/tag_blue_delete.png");
	private static final String ACTION_NAME = "Remove VTMatch Tags";

	private int tagCount = 0;

	public RemoveMatchTagAction() {
		super(ACTION_NAME, VTPlugin.OWNER);

		setDescription("Remove Match Tag");
		setToolBarData(new ToolBarData(EDIT_TAG_ICON, MENU_GROUP));
		MenuData menuData = new MenuData(new String[] { "Remove Tag" }, EDIT_TAG_ICON, MENU_GROUP);
		menuData.setMenuSubGroup("2"); // after the Chooser... action
		setPopupMenuData(menuData);
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Remove_Tag"));

	}

	@Override
	public void actionPerformed(ActionContext context) {
		removeTag(context);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		tagCount = 0;
		if (!(context instanceof VTMatchContext)) {
			return false;
		}

		VTMatchContext matchContext = (VTMatchContext) context;
		List<VTMatch> matches = matchContext.getSelectedMatches();
		if (matches.size() == 0) {
			return false;
		}

		tagCount = calculateTagCount(matches);
		return tagCount > 0;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof VTMatchContext)) {
			return false;
		}
		VTMatchContext matchContext = (VTMatchContext) context;
		List<VTMatch> matches = matchContext.getSelectedMatches();
		if (matches.size() == 0) {
			return false;
		}
		return true;
	}

	private int calculateTagCount(List<VTMatch> matches) {
		int count = 0;
		for (VTMatch match : matches) {
			VTMatchTag tag = match.getTag();
			if (tag != null && tag != VTMatchTag.UNTAGGED) {
				count++;
			}
		}
		return count;
	}

	private void removeTag(ActionContext context) {
		VTMatchContext matchContext = (VTMatchContext) context;

		ComponentProvider componentProvider = matchContext.getComponentProvider();
		JComponent component = componentProvider.getComponent();

		String message = "1 tag?";
		if (tagCount > 1) {
			message = tagCount + " tags?";
		}

		int choice =
			OptionDialog.showYesNoDialog(component, "Remove Match Tag?", "Remove " + message);
		if (choice == OptionDialog.NO_OPTION) {
			return;
		}

		List<VTMatch> matches = matchContext.getSelectedMatches();
		ClearMatchTagTask task = new ClearMatchTagTask(matchContext.getSession(), matches);
		new TaskLauncher(task, component);
	}
}

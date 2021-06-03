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
package ghidra.app.plugin.core.navigation;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.Icon;

import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * The NextPrevCodeUnitPlugin generates a GoTo event based on where the cursor
 * is located in the program. The GoTo events provided by this plugin are:
 * <UL>
 * <LI>Next-Previous Instruction
 * <LI>Next-Previous Defined Data
 * <LI>Next-Previous Undefined Data
 * <LI>Next-Previous Function
 * <LI>Next-Previous Non-Function
 * <LI>Next-Previous Label
 * <LI>Next-Previous Bookmark
 * </UL>
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.NAVIGATION,
	shortDescription = "Go To Next/Previous Code Unit",
	description = "This plugin moves the current location to the next or previous instruction, defined data, or undefined data in the program.",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class NextPrevCodeUnitPlugin extends Plugin {
	private DockingAction toggleDirectionAction;
	private AbstractNextPreviousAction instructionAction;
	private AbstractNextPreviousAction dataAction;
	private AbstractNextPreviousAction undefinedAction;
	private AbstractNextPreviousAction functionAction;
	private AbstractNextPreviousAction nonFunctionAction;
	private AbstractNextPreviousAction labelAction;
	private NextPreviousBookmarkAction bookmarkAction;
	private NextPreviousDifferentByteAction differentValueAction;

	public NextPrevCodeUnitPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	private void createActions() {
		// use this index to make sure that the following actions are ordered in the way that 
		// they are inserted
		int subGroupIndex = 0;

		toggleDirectionAction = new ToggleDirectionAction("" + subGroupIndex++);
		tool.addAction(toggleDirectionAction);

		instructionAction =
			new NextPreviousInstructionAction(tool, getName(), "" + subGroupIndex++);
		tool.addAction(instructionAction);

		dataAction = new NextPreviousDefinedDataAction(tool, getName(), "" + subGroupIndex++);
		tool.addAction(dataAction);

		undefinedAction = new NextPreviousUndefinedAction(tool, getName(), "" + subGroupIndex++);
		tool.addAction(undefinedAction);

		labelAction = new NextPreviousLabelAction(tool, getName(), "" + subGroupIndex++);
		tool.addAction(labelAction);

		functionAction = new NextPreviousFunctionAction(tool, getName(), "" + subGroupIndex++);
		tool.addAction(functionAction);

		nonFunctionAction =
			new NextPreviousNonFunctionAction(tool, getName(), "" + subGroupIndex++);
		tool.addAction(nonFunctionAction);

		differentValueAction =
			new NextPreviousDifferentByteAction(tool, getName(), "" + subGroupIndex++);
		tool.addAction(differentValueAction);

		bookmarkAction = new NextPreviousBookmarkAction(tool, getName(), "" + subGroupIndex++);
		tool.addAction(bookmarkAction);
	}

	private void updateActions(boolean searchForward) {
		instructionAction.setDirection(searchForward);
		dataAction.setDirection(searchForward);
		undefinedAction.setDirection(searchForward);
		functionAction.setDirection(searchForward);
		nonFunctionAction.setDirection(searchForward);
		labelAction.setDirection(searchForward);
		differentValueAction.setDirection(searchForward);
		bookmarkAction.setDirection(searchForward);
	}

	private class ToggleDirectionAction extends NavigatableContextAction {
		Icon forwardIcon = ResourceManager.loadImage("images/down.png");
		Icon backwardIcon = ResourceManager.loadImage("images/up.png");
		private boolean isForward = true;

		ToggleDirectionAction(String subGroup) {
			super("Toggle Search Direction", NextPrevCodeUnitPlugin.this.getName());
			setToolBarData(new ToolBarData(forwardIcon,
				ToolConstants.TOOLBAR_GROUP_FOUR, subGroup));
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_T, InputEvent.CTRL_DOWN_MASK |
				InputEvent.ALT_DOWN_MASK));

			String longName = "Toggle Code Unit Search Direction";
			setHelpLocation(
				new HelpLocation(HelpTopics.NAVIGATION, longName));
			setDescription(longName);
			addToWindowWhen(NavigatableActionContext.class);

		}

		@Override
		public void actionPerformed(NavigatableActionContext context) {
			isForward = !isForward;
			getToolBarData().setIcon(isForward ? forwardIcon : backwardIcon);
			updateActions(isForward);
		}
	}
}

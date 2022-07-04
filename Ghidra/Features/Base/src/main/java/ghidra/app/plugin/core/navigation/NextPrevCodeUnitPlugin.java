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

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import generic.util.image.ImageUtils;
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
	private InvertStateAction invertStateAction;
	private AbstractNextPreviousAction instructionAction;
	private AbstractNextPreviousAction dataAction;
	private AbstractNextPreviousAction undefinedAction;
	private AbstractNextPreviousAction functionAction;
	private AbstractNextPreviousAction labelAction;
	private NextPreviousBookmarkAction bookmarkAction;
	private NextPreviousSameBytesAction sameValueAction;

	public NextPrevCodeUnitPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	private void createActions() {
		// use this index to ensure the actions are ordered in the way that they are inserted
		char subGroupChar = 'a';

		toggleDirectionAction = new ToggleDirectionAction(String.valueOf(subGroupChar++));
		tool.addAction(toggleDirectionAction);

		invertStateAction = new InvertStateAction(String.valueOf(subGroupChar++));
		tool.addAction(invertStateAction);

		instructionAction =
			new NextPreviousInstructionAction(tool, getName(), String.valueOf(subGroupChar++));
		tool.addAction(instructionAction);

		dataAction =
			new NextPreviousDefinedDataAction(tool, getName(), String.valueOf(subGroupChar++));
		tool.addAction(dataAction);

		undefinedAction =
			new NextPreviousUndefinedAction(tool, getName(), String.valueOf(subGroupChar++));
		tool.addAction(undefinedAction);

		labelAction = new NextPreviousLabelAction(tool, getName(), String.valueOf(subGroupChar++));
		tool.addAction(labelAction);

		functionAction =
			new NextPreviousFunctionAction(tool, getName(), String.valueOf(subGroupChar++));
		tool.addAction(functionAction);

		sameValueAction =
			new NextPreviousSameBytesAction(tool, getName(), String.valueOf(subGroupChar++));
		tool.addAction(sameValueAction);

		bookmarkAction =
			new NextPreviousBookmarkAction(tool, getName(), String.valueOf(subGroupChar++));
		tool.addAction(bookmarkAction);
	}

	private void updateActionsDirection(boolean searchForward) {
		instructionAction.setDirection(searchForward);
		dataAction.setDirection(searchForward);
		undefinedAction.setDirection(searchForward);
		functionAction.setDirection(searchForward);
		labelAction.setDirection(searchForward);
		sameValueAction.setDirection(searchForward);
		bookmarkAction.setDirection(searchForward);
	}

	private void updatedActionsLogic(boolean isInverted) {
		instructionAction.setInverted(isInverted);
		dataAction.setInverted(isInverted);
		undefinedAction.setInverted(isInverted);
		functionAction.setInverted(isInverted);
		labelAction.setInverted(isInverted);
		sameValueAction.setInverted(isInverted);
		bookmarkAction.setInverted(isInverted);
	}

	private class InvertStateAction extends ToggleDockingAction {

		private final Icon INVERTED_ICON_OFF = ImageUtils.makeTransparent(
			ResourceManager.loadImage("images/dialog-cancel.png"));
		private final Icon INVERTED_ICON_ON = ImageUtils.makeTransparent(
			ResourceManager.loadImage("images/dialog-cancel.png"), .8f);
		private boolean isInverted = false;

		public InvertStateAction(String subGroup) {
			super("Invert Search Logic", NextPrevCodeUnitPlugin.this.getName());

			setToolBarData(new ToolBarData(INVERTED_ICON_OFF,
				ToolConstants.TOOLBAR_GROUP_FOUR, subGroup));

			// TODO add help entry
			setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, getName()));

			// TODO setDescriptoin("...");
			setSelected(false);

			addToWindowWhen(NavigatableActionContext.class);
		}

		@Override
		public void setSelected(boolean isSelected) {
			super.setSelected(isSelected);
			getToolBarData().setIcon(isSelected ? INVERTED_ICON_ON : INVERTED_ICON_OFF);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			isInverted = isSelected();
			updatedActionsLogic(isInverted);
		}
	}

	private class ToggleDirectionAction extends NavigatableContextAction {
		private final Icon FORWARD_ICON = ResourceManager.loadImage("images/down.png");
		private final Icon BACKWARD_ICON = ResourceManager.loadImage("images/up.png");
		private boolean isForward = true;

		ToggleDirectionAction(String subGroup) {
			super("Toggle Search Direction", NextPrevCodeUnitPlugin.this.getName());
			setToolBarData(new ToolBarData(FORWARD_ICON,
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
			getToolBarData().setIcon(isForward ? FORWARD_ICON : BACKWARD_ICON);
			updateActionsDirection(isForward);
		}
	}
}

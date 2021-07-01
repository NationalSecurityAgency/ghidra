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
package ghidra.app.util.viewer.listingpanel;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import ghidra.program.util.ListingDiff;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import resources.MultiIcon;
import resources.ResourceManager;

/**
 * Manages the actions that control a ListingDiff.
 */
public class ListingDiffActionManager {

	private static final String HELP_TOPIC = "FunctionComparison";
	private static final Icon NOT_ICON = ResourceManager.loadImage("images/no_small.png");
	private static final Icon BYTE_DIFFS_ICON = ResourceManager.loadImage("images/binaryData.gif");
	private static final Icon NO_BYTE_DIFFS_ICON = new MultiIcon(BYTE_DIFFS_ICON, NOT_ICON);
	private static final Icon DIFF_CONSTANTS_ICON =
		ResourceManager.loadImage("images/class.png");
	private static final Icon IGNORE_CONSTANTS_ICON = new MultiIcon(DIFF_CONSTANTS_ICON, NOT_ICON);
	private static final Icon DIFF_REGISTERS_ICON =
		ResourceManager.loadImage("images/registerGroup.png");
	private static final Icon IGNORE_REGISTERS_ICON = new MultiIcon(DIFF_REGISTERS_ICON, NOT_ICON);

	private static final String ACTION_GROUP = "A4_Diff";
	private DockingAction toggleIgnoreByteDiffsAction;
	private DockingAction toggleIgnoreConstantsAction;
	private DockingAction toggleIgnoreRegisterNamesAction;

	private ListingDiff listingDiff;

	/**
	 * Constructor for the action manager for a ListingDiff.
	 * @param listingDiff the ListingDiff that is controlled by this manager's docking actions.
	 */
	public ListingDiffActionManager(ListingDiff listingDiff) {
		this.listingDiff = listingDiff;
		createActions();
	}

	/**
	 * Creates the actions.
	 */
	protected void createActions() {
		toggleIgnoreByteDiffsAction = new ToggleIgnoreByteDiffsAction();
		toggleIgnoreConstantsAction = new ToggleIgnoreConstantsAction();
		toggleIgnoreRegisterNamesAction = new ToggleIgnoreRegisterNamesAction();
	}

	/**
	 * Gets the actions.
	 * @return the docking actions.
	 */
	public DockingAction[] getActions() {
		return new DockingAction[] { toggleIgnoreByteDiffsAction, toggleIgnoreConstantsAction,
			toggleIgnoreRegisterNamesAction };
	}

	/**
	 * Update the enablement of the actions created by this manager.
	 * @param isShowing true indicates that the dual listing diff is currently visible on screen.
	 */
	public void updateActionEnablement(boolean isShowing) {
		toggleIgnoreByteDiffsAction.setEnabled(isShowing);
		toggleIgnoreConstantsAction.setEnabled(isShowing);
		toggleIgnoreRegisterNamesAction.setEnabled(isShowing);
	}

	class ToggleIgnoreByteDiffsAction extends DualListingToggleDockingAction {

		ToggleIgnoreByteDiffsAction() {
			super("Toggle Ignore Byte Diffs", "DualListing");
			setDescription(HTMLUtilities.toHTML("If selected, difference highlights should\n"
				+ "ignore Byte differences."));
			setEnabled(true);
			setPopupMenuData(new MenuData(new String[] { "Ignore Bytes As Differences" },
				BYTE_DIFFS_ICON,
				ACTION_GROUP));
			ToolBarData newToolBarData = new ToolBarData(BYTE_DIFFS_ICON, ACTION_GROUP);
			setToolBarData(newToolBarData);

			setHelpLocation(new HelpLocation(HELP_TOPIC, "Dual Listing Ignore Bytes"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			listingDiff.setIgnoreByteDiffs(!listingDiff.isIgnoringByteDiffs());
		}

		@Override
		public void setSelected(boolean selected) {
			getToolBarData().setIcon(selected ? NO_BYTE_DIFFS_ICON : BYTE_DIFFS_ICON);
			super.setSelected(selected);
		}
	}

	class ToggleIgnoreConstantsAction extends DualListingToggleDockingAction {

		ToggleIgnoreConstantsAction() {
			super("Toggle Ignore Constants", "DualListing");
			setDescription(HTMLUtilities.toHTML("If selected, difference highlights should\n"
				+ "ignore operand Constants."));
			setEnabled(true);
			setPopupMenuData(new MenuData(
				new String[] { "Ignore Operand Constants As Differences" },
				DIFF_CONSTANTS_ICON,
				ACTION_GROUP));
			ToolBarData newToolBarData = new ToolBarData(DIFF_CONSTANTS_ICON, ACTION_GROUP);
			setToolBarData(newToolBarData);

			setHelpLocation(new HelpLocation(HELP_TOPIC, "Dual Listing Ignore Operand Constants"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			listingDiff.setIgnoreConstants(!listingDiff.isIgnoringConstants());
		}

		@Override
		public void setSelected(boolean selected) {
			getToolBarData().setIcon(selected ? IGNORE_CONSTANTS_ICON : DIFF_CONSTANTS_ICON);
			super.setSelected(selected);
		}
	}

	class ToggleIgnoreRegisterNamesAction extends DualListingToggleDockingAction {

		ToggleIgnoreRegisterNamesAction() {
			super("Toggle Ignore Register Names", "DualListing");
			setDescription(HTMLUtilities.toHTML("If selected, difference highlights should\n"
				+ "ignore operand Registers."));
			setEnabled(true);
			setPopupMenuData(new MenuData(
				new String[] { "Ignore Operand Registers As Differences" },
				DIFF_REGISTERS_ICON, ACTION_GROUP));
			ToolBarData newToolBarData = new ToolBarData(DIFF_REGISTERS_ICON, ACTION_GROUP);
			setToolBarData(newToolBarData);

			setHelpLocation(new HelpLocation(HELP_TOPIC, "Dual Listing Ignore Operand Registers"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			listingDiff.setIgnoreRegisters(!listingDiff.isIgnoringRegisters());
		}

		@Override
		public void setSelected(boolean selected) {
			getToolBarData().setIcon(selected ? IGNORE_REGISTERS_ICON : DIFF_REGISTERS_ICON);
			super.setSelected(selected);
		}
	}
}

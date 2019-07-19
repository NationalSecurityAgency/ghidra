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
package ghidra.app.plugin.core.diff;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.codebrowser.OtherPanelContext;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.listing.Program;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * Creates the actions for the program diff plugin.
 */
class DiffActionManager {

	private static final String SELECT_GROUP = "Select";
	private static final String GET_DIFF_GROUP = "GetDiff";
	private static final String DIFF_INFO_GROUP = "DiffInfo";
	private static final String DIFF_NAVIGATE_GROUP = "DiffNavigate";
	private static final String TOGGLE_VIEW_ICON_NAME = "images/table_relationship.png";
	private static final String GROUP = "Diff";
	private ProgramDiffPlugin plugin;
	private CodeViewerService codeViewerService;

	static final String APPLY_DIFFS_ACTION = "Apply Differences";
	static final String APPLY_DIFFS_NEXT_ACTION = "Apply Differences and Goto Next Difference";
	static final String IGNORE_DIFFS_NEXT_ACTION = "Ignore Selection and Goto Next Difference";
	static final String NEXT_DIFF_ACTION = "Next Difference";
	static final String PREVIOUS_DIFF_ACTION = "Previous Difference";
	static final String DIFF_DETAILS_ACTION = "Show Diff Location Details";
	static final String SHOW_DIFF_SETTINGS_ACTION = "Show Diff Apply Settings";
	static final String GET_DIFFS_ACTION = "Get Differences";
	static final String SELECT_ALL_DIFFS_ACTION = "Select All Differences";
	static final String P1_SELECT_TO_P2_ACTION = "Set Program1 Selection On Program2";
	static final String OPEN_CLOSE_PROGRAM2_ACTION = "Open/Close Program View";
	static final String VIEW_PROGRAM_DIFF_ACTION = "View Program Differences";

	private DockingAction applyDiffsAction;
	private DockingAction applyDiffsNextAction;
	private DockingAction ignoreDiffsAction;
	private DockingAction nextDiffAction;
	private DockingAction previousDiffAction;
	private DockingAction diffDetailsAction;
	private DockingAction showDiffSettingsAction;
	private DockingAction getDiffsAction;
	private DockingAction selectAllDiffsAction;
	private DockingAction p1SelectToP2Action;
	private ToggleDockingAction openCloseProgram2Action;
	private DockingAction viewProgramDiffAction;

	/**
	 * Creates an action manager for the Program Diff plugin.
	 */
	public DiffActionManager(ProgramDiffPlugin plugin) {
		this.plugin = plugin;
		createActions();
	}

	/**
	 * Sets the code viewer service that the Program Diff will use for setting local actions.
	 * @param codeViewerService the code viewer service
	 */
	void setCodeViewerService(CodeViewerService codeViewerService) {
		this.codeViewerService = codeViewerService;
		codeViewerService.addLocalAction(openCloseProgram2Action);
	}

	/**
	 * Adds the Program Diff's local actions to the code viewer.
	 */
	void addActions() {
		codeViewerService.addLocalAction(applyDiffsAction);
		codeViewerService.addLocalAction(applyDiffsNextAction);
		codeViewerService.addLocalAction(ignoreDiffsAction);
		codeViewerService.addLocalAction(diffDetailsAction);
		codeViewerService.addLocalAction(nextDiffAction);
		codeViewerService.addLocalAction(previousDiffAction);
		codeViewerService.addLocalAction(showDiffSettingsAction);
		codeViewerService.addLocalAction(getDiffsAction);
		codeViewerService.addLocalAction(selectAllDiffsAction);
		codeViewerService.addLocalAction(p1SelectToP2Action);
	}

	/**
	 * Removes the Program Diff's local actions from the code viewer.
	 */
	void removeActions() {
		codeViewerService.removeLocalAction(applyDiffsAction);
		codeViewerService.removeLocalAction(applyDiffsNextAction);
		codeViewerService.removeLocalAction(ignoreDiffsAction);
		codeViewerService.removeLocalAction(diffDetailsAction);
		codeViewerService.removeLocalAction(nextDiffAction);
		codeViewerService.removeLocalAction(previousDiffAction);
		codeViewerService.removeLocalAction(showDiffSettingsAction);
		codeViewerService.removeLocalAction(getDiffsAction);
		codeViewerService.removeLocalAction(selectAllDiffsAction);
		codeViewerService.removeLocalAction(p1SelectToP2Action);
	}

	/**
	 * Called to adjust the Program Diff's actions when a program is closed.
	 * @param program the closed program
	 */
	void programClosed(Program program) {
		boolean hasProgram = (plugin.getCurrentProgram() != null);
		openCloseProgram2Action.setEnabled(hasProgram && !plugin.isTaskInProgress());
	}

	/**
	 * Called to adjust or add/remove the Program Diff's actions when a program
	 * becomes the active program.
	 * @param program the newly active program
	 */
	void setActiveProgram(Program program) {
		viewProgramDiffAction.setEnabled(program != null);

		boolean enabled = program != null && !plugin.isTaskInProgress();
		openCloseProgram2Action.setEnabled(enabled);

		if (enabled) {
			if (openCloseProgram2Action.isSelected()) {
				// we are diffing--is the current program the diff program?
				Program firstProgram = plugin.getFirstProgram();
				if (firstProgram == program) {
					openCloseProgram2Action.setDescription("Close Diff View");
				}
				else {
					openCloseProgram2Action.setDescription("Bring Diff View to Front");
				}
			}
		}
		else {
			// no active diff
			openCloseProgram2Action.setDescription("Open Diff View");
		}
	}

	/**
	 * Notification to the action manager that a program was opened as the
	 * second program to the program Diff. Actions are adjusted accordingly.
	 */
	void secondProgramOpened() {
		openCloseProgram2Action.setSelected(true);
		openCloseProgram2Action.setDescription("Close Diff View");

		Program firstProgram = plugin.getFirstProgram();
		Program secondProgram = plugin.getSecondProgram();
		String firstName = firstProgram.getName();
		String secondName = secondProgram.getName();

		//@formatter:off
		openCloseProgram2Action.setDescription(
			"<html><center>Close Diff View</center><br>" +
			"Current diff: " +
			"<b>"+HTMLUtilities.escapeHTML(firstName)+"</b> to <b>" +HTMLUtilities.escapeHTML(secondName)+"</b>");
		//@formatter:on
	}

	/**
	 * Notification to the action manager that the second program to the
	 * program Diff was closed. Actions are adjusted accordingly.
	 */
	void secondProgramClosed() {
		openCloseProgram2Action.setSelected(false);
		openCloseProgram2Action.setDescription("Open Diff View");
		showDiffSettingsAction.setEnabled(false);
		diffDetailsAction.setEnabled(false);
		removeActions();
	}

	void setP1SelectToP2ActionEnabled(boolean enabled) {
		p1SelectToP2Action.setEnabled(enabled);
	}

	void setOpenCloseActionSelected(boolean selected) {
		openCloseProgram2Action.setSelected(selected);
	}

	void updateActions(boolean taskInProgress, boolean inDiff, boolean hasSelectionInView,
			boolean applyFilterIsSet, boolean hasProgram2, boolean hasHighlights) {
		DiffController diffControl = plugin.getDiffController();
		applyDiffsAction.setEnabled(!taskInProgress && inDiff && hasSelectionInView);
		applyDiffsNextAction.setEnabled(
			!taskInProgress && inDiff && hasSelectionInView && diffControl.hasNext());
		ignoreDiffsAction.setEnabled(!taskInProgress && inDiff && hasSelectionInView);
		nextDiffAction.setEnabled(!taskInProgress && inDiff && diffControl.hasNext());
		previousDiffAction.setEnabled(!taskInProgress && inDiff && diffControl.hasPrevious());
		diffDetailsAction.setEnabled(!taskInProgress && hasProgram2);
		showDiffSettingsAction.setEnabled(!taskInProgress && inDiff);
		getDiffsAction.setEnabled(!taskInProgress && hasProgram2);
		selectAllDiffsAction.setEnabled(!taskInProgress && !inDiff || hasHighlights);
		p1SelectToP2Action.setEnabled(hasProgram2 && !plugin.getCurrentSelection().isEmpty());

		Program currentProgram = plugin.getCurrentProgram();
		boolean hasProgram = (currentProgram != null);
		openCloseProgram2Action.setEnabled(hasProgram && !taskInProgress);
	}

	/**
	 * Removes all the actions.
	 */
	void dispose() {
		codeViewerService.removeLocalAction(openCloseProgram2Action);
		plugin.getTool().removeAction(viewProgramDiffAction);
		removeActions();
	}

	private void createActions() {

		viewProgramDiffAction = new DockingAction(VIEW_PROGRAM_DIFF_ACTION, plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.selectProgram2();
			}
		};
		String[] menuPath = { ToolConstants.MENU_TOOLS, "Program &Differences..." };
		viewProgramDiffAction.setEnabled(plugin.getCurrentProgram() != null);
		viewProgramDiffAction.setMenuBarData(new MenuData(menuPath, "View"));
		viewProgramDiffAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_2, 0));
		viewProgramDiffAction.setHelpLocation(
			new HelpLocation(HelpTopics.DIFF, "Program_Differences"));
		plugin.getTool().addAction(viewProgramDiffAction);

		applyDiffsAction = new DiffAction(APPLY_DIFFS_ACTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.applyDiff();
			}
		};
		ImageIcon icon = ResourceManager.loadImage("images/pencil16.png");
		applyDiffsAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F3, 0));
		applyDiffsAction.setPopupMenuData(
			new MenuData(new String[] { "Apply Selection" }, icon, GROUP));
		applyDiffsAction.setDescription(
			"Applies the differences from the second program's selection using the settings.");
		applyDiffsAction.setToolBarData(new ToolBarData(icon, GROUP));

		applyDiffsNextAction = new DiffAction(APPLY_DIFFS_NEXT_ACTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.applyDiffAndGoNext();
			}
		};
		icon = ResourceManager.loadImage("images/pencil_arrow16.png");
		String[] applyDiffsPath = { "Apply Selection and Goto Next Difference" };
		applyDiffsNextAction.setPopupMenuData(new MenuData(applyDiffsPath, icon, GROUP));
		applyDiffsNextAction.setKeyBindingData(
			new KeyBindingData(KeyEvent.VK_F3, InputEvent.SHIFT_DOWN_MASK));
		applyDiffsNextAction.setToolBarData(new ToolBarData(icon, GROUP));
		applyDiffsNextAction.setDescription(
			"Applies the differences from the second program's selection using the settings.  " +
				"Then moves the cursor to the next difference.");

		ignoreDiffsAction = new DiffAction(IGNORE_DIFFS_NEXT_ACTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.ignoreDiff();
			}
		};
		icon = ResourceManager.loadImage("images/eraser_arrow16.png");
		ignoreDiffsAction.setPopupMenuData(new MenuData(
			new String[] { "Ignore Selection and Goto Next Difference" }, icon, GROUP));
		ignoreDiffsAction.setDescription(
			"Ignores the selected program differences and moves the cursor to the next difference.");
		ignoreDiffsAction.setToolBarData(new ToolBarData(icon, GROUP));

		nextDiffAction = new DiffAction(NEXT_DIFF_ACTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.nextDiff();
			}
		};
		icon = ResourceManager.loadImage("images/down.png");
		nextDiffAction.setKeyBindingData(
			new KeyBindingData('N', InputEvent.CTRL_MASK | InputEvent.ALT_MASK));
		nextDiffAction.setPopupMenuData(
			new MenuData(new String[] { "Next Difference" }, icon, DIFF_NAVIGATE_GROUP));
		nextDiffAction.setToolBarData(new ToolBarData(icon, DIFF_NAVIGATE_GROUP));
		nextDiffAction.setDescription("Go to the next highlighted difference.");

		previousDiffAction = new DiffAction(PREVIOUS_DIFF_ACTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.previousDiff();
			}
		};
		icon = ResourceManager.loadImage("images/up.png");
		previousDiffAction.setKeyBindingData(
			new KeyBindingData('P', InputEvent.CTRL_MASK | InputEvent.ALT_MASK));
		previousDiffAction.setPopupMenuData(
			new MenuData(new String[] { "Previous Difference" }, icon, DIFF_NAVIGATE_GROUP));
		previousDiffAction.setToolBarData(new ToolBarData(icon, DIFF_NAVIGATE_GROUP));
		previousDiffAction.setDescription("Go to previous highlighted difference.");

		diffDetailsAction = new DiffAction(DIFF_DETAILS_ACTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.showDiffDetails();
			}
		};
		icon = ResourceManager.loadImage("images/xmag.png");
		diffDetailsAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F5, 0));
		diffDetailsAction.setPopupMenuData(
			new MenuData(new String[] { "Location Details..." }, icon, DIFF_INFO_GROUP));
		diffDetailsAction.setToolBarData(new ToolBarData(icon, DIFF_INFO_GROUP));
		diffDetailsAction.setDescription(
			"Show details of the program differences at the current location.");

		showDiffSettingsAction = new DiffAction(SHOW_DIFF_SETTINGS_ACTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.showDiffApplySettings();
			}
		};
		showDiffSettingsAction.setPopupMenuData(
			new MenuData(new String[] { "Show Diff Apply Settings..." }, GET_DIFF_GROUP));
		showDiffSettingsAction.setDescription(
			"Displays the current program difference apply settings.");
		showDiffSettingsAction.setToolBarData(
			new ToolBarData(DiffApplySettingsProvider.ICON, GET_DIFF_GROUP));

		getDiffsAction = new DiffAction(GET_DIFFS_ACTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.diff();
			}
		};
		icon = ResourceManager.loadImage("images/Diff16.png");
		getDiffsAction.setPopupMenuData(
			new MenuData(new String[] { "Get Differences..." }, icon, GET_DIFF_GROUP));
		getDiffsAction.setToolBarData(new ToolBarData(icon, GET_DIFF_GROUP));
		getDiffsAction.setDescription("Determines program differences.");

		selectAllDiffsAction = new DiffAction(SELECT_ALL_DIFFS_ACTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.selectAllDiffs();
			}
		};
		selectAllDiffsAction.setPopupMenuData(
			new MenuData(new String[] { "Select All Differences" }, SELECT_GROUP));
		selectAllDiffsAction.setDescription(
			"Selects all highlighted differences in the second program.");

		p1SelectToP2Action = new DiffAction(P1_SELECT_TO_P2_ACTION) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.setP1SelectionOnP2();
			}
		};
		icon = ResourceManager.loadImage("images/DiffSelect16.png");
		p1SelectToP2Action.setDescription(
			"Select Program 2 highlights using selection in Program 1.");
		p1SelectToP2Action.setToolBarData(new ToolBarData(icon, SELECT_GROUP));

		openCloseProgram2Action =
			new ToggleDockingAction(OPEN_CLOSE_PROGRAM2_ACTION, plugin.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					//
					// No active diff--start one.
					//
					if (openCloseProgram2Action.isSelected()) {
						plugin.selectProgram2();
						return;
					}

					//
					// We have a diff session--is the current program the one for the diff session?
					// If not, simply make the diff program the active program (this is useful for
					// users when they were diffing, but then opened a different program).
					//
					if (activateDiffProgram()) {
						// clicking the action will change the selected state--keep it selected
						setSelected(true);
						setDescription("Close Diff View");
						return;
					}

					//
					// Otherwise, close the diff.
					//
					closeDiff();
				}

				private void closeDiff() {
					int choice = OptionDialog.showYesNoCancelDialog(null, "Close Diff Session",
						"Close the current diff session?");
					if (choice == OptionDialog.YES_OPTION) {
						plugin.closeProgram2();
						setDescription("Open Diff View");
					}
					else {
						// clicking the action will change the selected state--keep it selected
						setSelected(true);
						setDescription("Close Diff View");
					}
				}

				private boolean activateDiffProgram() {

					Program currentProgram = plugin.getCurrentProgram();
					Program firstProgram = plugin.getFirstProgram();
					boolean isFirstProgram = (firstProgram == currentProgram);
					if (isFirstProgram) {
						return false; // already active--nothing to do!
					}

					plugin.activeProgram(firstProgram);
					return true;
				}
			};
		icon = ResourceManager.loadImage(TOGGLE_VIEW_ICON_NAME);
		openCloseProgram2Action.setEnabled(false);
		openCloseProgram2Action.setKeyBindingData(
			new KeyBindingData('C', InputEvent.CTRL_MASK | InputEvent.ALT_MASK));
		openCloseProgram2Action.setToolBarData(new ToolBarData(icon, "zzz"));
		openCloseProgram2Action.setHelpLocation(
			new HelpLocation(HelpTopics.DIFF, OPEN_CLOSE_PROGRAM2_ACTION));
		openCloseProgram2Action.setSelected(false);
		openCloseProgram2Action.setDescription("Open Diff View");
	}

	private abstract class DiffAction extends DockingAction {
		DiffAction(String name) {
			super(name, plugin.getName());
			setHelpLocation(new HelpLocation(HelpTopics.DIFF, name));
			setEnabled(false);
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return (context instanceof OtherPanelContext);
		}
	}
}

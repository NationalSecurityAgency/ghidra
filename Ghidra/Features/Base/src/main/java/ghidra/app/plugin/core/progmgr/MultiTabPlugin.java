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
package ghidra.app.plugin.core.progmgr;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;
import javax.swing.Timer;

import docking.ActionContext;
import docking.DockingUtils;
import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * Plugin to show a "tab" for each open program; the selected tab is the activated program.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Open/close programs",
	description = "This plugin provides actions for opening and "
			+ "closing multiple programs. A tab is displayed in the "
			+ "Code Browser when there is more than one open program",
	servicesRequired = { ProgramManager.class, CodeViewerService.class },
	eventsConsumed = { ProgramOpenedPluginEvent.class, ProgramClosedPluginEvent.class, ProgramActivatedPluginEvent.class, ProgramVisibilityChangePluginEvent.class }
)
//@formatter:on
public class MultiTabPlugin extends Plugin implements DomainObjectListener {

	//
	// Unusual Code Alert!: We can't initialize these in the fields above because calling
	// DockingUtils calls into Swing code.  Further, we don't want Swing code being accessed
	// when the Plugin classes are loaded, as they get loaded in the headless environment.
	// 
	private final KeyStroke NEXT_TAB_KEYSTROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_F9, DockingUtils.CONTROL_KEY_MODIFIER_MASK);
	private final KeyStroke PREVIOUS_TAB_KEYSTROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_F8, DockingUtils.CONTROL_KEY_MODIFIER_MASK);

	private MultiTabPanel tabPanel;
	private ProgramManager progService;
	private CodeViewerService cvService;
	private DockingAction goToProgramAction;
	private DockingAction goToLastActiveProgramAction;
	private Program lastActiveProgram;
	private Program currentProgram;
	private DockingAction goToNextProgramAction;
	private DockingAction goToPreviousProgramAction;

	private Timer selectHighlightedProgramTimer;

	public MultiTabPlugin(PluginTool tool) {
		super(tool);

		createActions();
	}

	private void createActions() {

		String firstGroup = "1";
		String secondGroup = "2";

		goToProgramAction = new DockingAction("Go To Program", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showProgramList();
			}
		};
		goToProgramAction.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_NAVIGATION, "Go To Program..." }, null,
				ToolConstants.MENU_NAVIGATION_GROUP_WINDOWS, MenuData.NO_MNEMONIC, firstGroup));
		goToProgramAction.setKeyBindingData(
			new KeyBindingData(KeyEvent.VK_F7, InputEvent.CTRL_DOWN_MASK));

		goToProgramAction.setEnabled(false);
		goToProgramAction.setDescription(
			"Shows the program selection dialog with the current program selected");
		goToProgramAction.setHelpLocation(
			new HelpLocation("ProgramManagerPlugin", "Go_To_Program"));

		goToNextProgramAction = new DockingAction("Go To Next Program", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				// highlight the next tab
				nextProgramPressed();
			}
		};
		goToNextProgramAction.setEnabled(false);
		goToNextProgramAction.setDescription(
			"Highlights the next program tab and then switches to that program");
		goToNextProgramAction.setKeyBindingData(new KeyBindingData(NEXT_TAB_KEYSTROKE));
		goToNextProgramAction.setHelpLocation(
			new HelpLocation("ProgramManagerPlugin", "Go_To_Next_And_Previous_Program"));

		goToPreviousProgramAction = new DockingAction("Go To Previous Program", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				// highlight the previous tab
				previousProgramPressed();
			}
		};
		goToPreviousProgramAction.setEnabled(false);
		goToPreviousProgramAction.setKeyBindingData(new KeyBindingData(PREVIOUS_TAB_KEYSTROKE));
		goToPreviousProgramAction.setDescription(
			"Highlights the previous program tab and then switches to that program");
		goToPreviousProgramAction.setHelpLocation(
			new HelpLocation("ProgramManagerPlugin", "Go_To_Next_And_Previous_Program"));

		// this timer is to give the user time to select successive programs before activating one 
		selectHighlightedProgramTimer = new Timer(750, e -> selectHighlightedProgram());
		selectHighlightedProgramTimer.setRepeats(false);

		goToLastActiveProgramAction = new DockingAction("Go To Last Active Program", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				switchToProgram(lastActiveProgram);
			}
		};
		goToLastActiveProgramAction.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_NAVIGATION, "Go To Last Active Program" }, null,
			ToolConstants.MENU_NAVIGATION_GROUP_WINDOWS, MenuData.NO_MNEMONIC, secondGroup));
		goToLastActiveProgramAction.setKeyBindingData(
			new KeyBindingData(KeyEvent.VK_F6, InputEvent.CTRL_DOWN_MASK));
		goToLastActiveProgramAction.setEnabled(false);
		goToLastActiveProgramAction.setDescription(
			"Activates the last program used before the current program");
		goToLastActiveProgramAction.setHelpLocation(
			new HelpLocation("ProgramManagerPlugin", "Go_To_Last_Active_Program"));

		tool.addAction(goToProgramAction);
		tool.addAction(goToLastActiveProgramAction);
		tool.addAction(goToNextProgramAction);
		tool.addAction(goToPreviousProgramAction);
	}

	private void updateActionEnablement() {
		// the next/previous actions should not be enabled if no tabs are hidden
		boolean enable = (tabPanel.getTabCount() > 1);
		goToProgramAction.setEnabled(enable);
		goToNextProgramAction.setEnabled(enable);
		goToPreviousProgramAction.setEnabled(enable);

		enable = (lastActiveProgram != null);
		goToLastActiveProgramAction.setEnabled(enable);
	}

	private void switchToProgram(Program program) {
		if (lastActiveProgram != null) {
			tabPanel.setSelectedProgram(lastActiveProgram);
		}
	}

	private void showProgramList() {
		tabPanel.showProgramList();
	}

	private void highlightNextProgram(boolean forwardDirection) {
		tabPanel.highlightNextProgram(forwardDirection);
	}

	private void selectHighlightedProgram() {
		tabPanel.selectHighlightedProgram();
	}

	String getStringUsedInList(Program program) {
		DomainFile df = program.getDomainFile();
		String changeIndicator = program.isChanged() ? "*" : "";
		if (!df.isInWritableProject()) {
			return df.toString() + " [Read-Only]" + changeIndicator;
		}
		return df.toString() + changeIndicator;
	}

	String getToolTip(Program program) {
		return getStringUsedInList(program);
	}

	String getName(Program program) {
		DomainFile df = program.getDomainFile();
		String tabName = df.getName();
		if (df.isReadOnly()) {
			int version = df.getVersion();
			if (!df.canSave() && version != DomainFile.DEFAULT_VERSION) {
				tabName += "@" + version;
			}
			tabName = tabName + " [Read-Only]";
		}
		return tabName;
	}

	void keyTypedFromListWindow(KeyEvent e) {

		KeyStroke stroke = KeyStroke.getKeyStrokeForEvent(e);
		if (stroke.equals(NEXT_TAB_KEYSTROKE)) {
			nextProgramPressed();
		}
		else if (stroke.equals(PREVIOUS_TAB_KEYSTROKE)) {
			previousProgramPressed();
		}
	}

	private void nextProgramPressed() {
		highlightNextProgram(true);
		selectHighlightedProgramTimer.restart();
	}

	private void previousProgramPressed() {
		highlightNextProgram(false);
		selectHighlightedProgramTimer.restart();
	}

	boolean isChanged(Object obj) {
		return ((Program) obj).isChanged();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.getSource() instanceof Program) {
			Program program = (Program) ev.getSource();
			tabPanel.refresh(program);
		}
	}

	@Override
	protected void init() {
		tabPanel = new MultiTabPanel(this);
		progService = tool.getService(ProgramManager.class);
		cvService = tool.getService(CodeViewerService.class);
		cvService.setNorthComponent(tabPanel);
	}

	boolean removeProgram(Program program) {
		return progService.closeProgram(program, false);
	}

	void programSelected(Program program) {
		if (program != progService.getCurrentProgram()) {
			progService.setCurrentProgram(program);
		}
	}

	private void add(Program prog) {

		if (progService.isVisible(prog)) {
			tabPanel.addProgram(prog);
			prog.removeListener(this);
			prog.addListener(this);
			updateActionEnablement();
		}
	}

	private void remove(Program prog) {
		prog.removeListener(this);
		tabPanel.removeProgram(prog);
		updateActionEnablement();
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramOpenedPluginEvent) {
			Program prog = ((ProgramOpenedPluginEvent) event).getProgram();
			add(prog);
		}
		else if (event instanceof ProgramClosedPluginEvent) {
			Program prog = ((ProgramClosedPluginEvent) event).getProgram();
			if (prog == lastActiveProgram) {
				lastActiveProgram = null;
			}
			if (prog == currentProgram) {
				currentProgram = null;
			}
			remove(prog);
		}
		else if (event instanceof ProgramActivatedPluginEvent) {
			Program prog = ((ProgramActivatedPluginEvent) event).getActiveProgram();
			lastActiveProgram = currentProgram;
			currentProgram = prog;

			if (prog != null) {
				add(prog);
				if (tabPanel.getSelectedProgram() != prog) {
					tabPanel.setSelectedProgram(prog);
					updateActionEnablement();
				}
			}
		}
		else if (event instanceof ProgramVisibilityChangePluginEvent) {
			Program prog = ((ProgramVisibilityChangePluginEvent) event).getProgram();
			if (progService.isVisible(prog)) {
				add(prog);
				if (progService.getCurrentProgram() != prog) {
					currentProgram = prog;
					tabPanel.setSelectedProgram(prog);
					updateActionEnablement();
				}
			}
			else {
				remove(prog);
				add(prog);
			}
		}
	}

	@Override
	protected void dispose() {
		selectHighlightedProgramTimer.stop();
		tabPanel.removeAll();
		cvService.setNorthComponent(null);
	}

}

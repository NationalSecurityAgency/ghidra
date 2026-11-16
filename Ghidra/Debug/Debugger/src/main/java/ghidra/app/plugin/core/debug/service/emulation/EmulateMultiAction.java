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
package ghidra.app.plugin.core.debug.service.emulation;

import static ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin.*;

import java.util.*;
import java.util.stream.Stream;

import javax.swing.*;

import docking.ActionContext;
import docking.PopupMenuHandler;
import docking.action.*;
import docking.menu.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingActionContext;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin.ConfigLast;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;

public class EmulateMultiAction extends MultiActionDockingAction {
	public static final String NAME = "Emulate";
	public static final Icon ICON = DebuggerResources.ICON_EMULATE;
	public static final String GROUP = DebuggerResources.GROUP_GENERAL;
	public static final String HELP_ANCHOR = "emulate_program";

	private final DebuggerEmulationServicePlugin plugin;
	private MenuActionDockingToolbarButton button;

	public EmulateMultiAction(DebuggerEmulationServicePlugin plugin) {
		super(NAME, plugin.getName());
		this.plugin = plugin;
		setToolBarData(new ToolBarData(ICON, GROUP, "B"));
		setHelpLocation(new HelpLocation(plugin.getName(), HELP_ANCHOR));
	}

	protected static String[] prependMenuPath(String pre, List<String> menuPath) {
		return Stream.concat(Stream.of(pre), menuPath.stream()).toArray(String[]::new);
	}

	public void collectActionsForProgram(List<DockingActionIf> actions, Program program) {
		actions.add(new EmulateProgramAction(plugin, program));
		actions.add(new EmulateTargetAction(plugin, program));
		actions.add(new EmulateFunctionAction(plugin, program));
	}

	@Override
	public List<DockingActionIf> getActionList(ActionContext context) {
		List<DockingActionIf> actions = getRestrictedActionList();
		if (context instanceof DebuggerListingActionContext plctx) {
			actions.add(new EmulateTargetAction(plugin, plctx.getProgram()));
		}
		ConfigLast last = plugin.findMostRecentConfig();
		if (last != null) {
			actions.add(new TopEmulateAction(plugin, last.configName(), last.program()));
		}
		return actions;
	}

	List<DockingActionIf> getRestrictedActionList() {
		ProgramManager programManager = plugin.getTool().getService(ProgramManager.class);
		List<Program> allPrograms = List.of(programManager.getAllOpenPrograms());
		List<DockingActionIf> actions = new ArrayList<>();
		for (Program program : allPrograms) {
			collectActionsForProgram(actions, program);
		}
		actions.add(new EmulateAddThreadAction(plugin));
		actions.add(new InvalidateEmulatorCacheAction(plugin));
		return actions;
	}

	class MenuActionDockingToolbarButton extends MultipleActionDockingToolbarButton {
		public MenuActionDockingToolbarButton(MultiActionDockingActionIf action) {
			super(action);
		}

		@Override
		protected JPopupMenu doCreateMenu() {
			ProgramManager programManager = plugin.getTool().getService(ProgramManager.class);
			Program currentProgram =
				programManager == null ? null : programManager.getCurrentProgram();
			ActionContext context = getActionContext();
			List<DockingActionIf> actionList = getActionList(context);
			MenuHandler handler =
				new PopupMenuHandler(plugin.getTool().getWindowManager(), context);
			MenuGroupMap groupMap = new MenuGroupMap();
			MenuManager manager =
				new MenuManager("Emulate", (char) 0, GROUP, true, handler, groupMap);
			for (DockingActionIf action : actionList) {
				if (action instanceof AbstractEmulateAction ea) {
					String[] path = action.getPopupMenuData().getMenuPath();
					String[] topPath = Arrays.copyOf(path, 1);
					groupMap.setMenuGroup(topPath,
						ea.getTopGroup(currentProgram),
						ea.getTopOrder(currentProgram));
				}
				action.setEnabled(action.isEnabledForContext(context));
				if (manager.getAction(action.getName()) == null) {
					manager.addAction(action);
				}
			}
			return manager.getPopupMenu();
		}

		@Override
		protected JPopupMenu showPopup() {
			// Make accessible to this file
			return super.showPopup();
		}

		@Override
		public String getToolTipText() {
			return getDescription();
		}
	}

	@Override
	public JButton doCreateButton() {
		return button = new MenuActionDockingToolbarButton(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		ConfigLast last = plugin.findMostRecentConfig();
		if (last == null) {
			Swing.runLater(() -> button.showPopup());
		}
		DockingActionIf action = plugin.getAction(last.configName());
		action.actionPerformed(context);
	}

	@Override
	public String getDescription() {
		ConfigLast last = plugin.findMostRecentConfig();
		if (last == null) {
			return "Emulate ...";
		}
		if (last.program() == null) {
			return "Empty session";
		}
		return "Re-emulate %s".formatted(getProgramName(last.program()));
	}

}

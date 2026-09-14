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
package ghidra.app.plugin.core.debug.gui.tracermi.launcher;

import static ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin.getProgramName;

import java.util.*;
import java.util.stream.Stream;

import javax.swing.*;

import docking.ActionContext;
import docking.PopupMenuHandler;
import docking.action.*;
import docking.menu.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin.ConfigLast;
import ghidra.app.services.ProgramManager;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;

public class LaunchAction extends MultiActionDockingAction {
	public static final String NAME = "Launch";
	public static final Icon ICON = DebuggerResources.ICON_DEBUGGER;
	public static final String GROUP = DebuggerResources.GROUP_GENERAL;
	public static final String HELP_ANCHOR = "launch_tracermi";

	private final TraceRmiLauncherServicePlugin plugin;
	private MenuActionDockingToolbarButton button;

	public LaunchAction(TraceRmiLauncherServicePlugin plugin) {
		super(NAME, plugin.getName());
		this.plugin = plugin;
		setToolBarData(new ToolBarData(ICON, GROUP, "A"));
		setHelpLocation(new HelpLocation(plugin.getName(), HELP_ANCHOR));
	}

	protected static String[] prependMenuPath(String pre, List<String> menuPath) {
		return Stream.concat(Stream.of(pre), menuPath.stream()).toArray(String[]::new);
	}

	static abstract class AbstractLaunchOfferAction extends DockingAction {
		final TraceRmiLauncherServicePlugin plugin;
		final TraceRmiLaunchOffer offer;

		public AbstractLaunchOfferAction(TraceRmiLauncherServicePlugin plugin,
				TraceRmiLaunchOffer offer) {
			this.plugin = plugin;
			this.offer = offer;
			super(offer.getConfigName(), plugin.getName());
			setHelpLocation(offer.getHelpLocation());
			setPopupMenuData(computeMenuData());
		}

		abstract MenuData computeMenuData();

		String getTopGroup(Program currentProgram) {
			return "";
		}

		String getTopOrder(Program currentProgram) {
			return "";
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return true;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			plugin.configureAndLaunch(offer);
		}
	}

	static class ProgramLaunchOfferAction extends AbstractLaunchOfferAction {
		final Program program;

		public ProgramLaunchOfferAction(TraceRmiLauncherServicePlugin plugin,
				TraceRmiLaunchOffer offer, Program program) {
			this.program = program;
			super(plugin, offer);
		}

		@Override
		MenuData computeMenuData() {
			return new MenuData(
				prependMenuPath("Launch %s ...".formatted(getProgramName(program)),
					offer.getMenuPath()),
				offer.getIcon(), offer.getMenuGroup(), 0, offer.getMenuOrder());
		}

		@Override
		String getTopGroup(Program currentProgram) {
			return "2";
		}

		@Override
		String getTopOrder(Program currentProgram) {
			return program == currentProgram ? "1" : "2";
		}
	}

	static class EmptyLaunchOfferAction extends AbstractLaunchOfferAction {
		public EmptyLaunchOfferAction(TraceRmiLauncherServicePlugin plugin,
				TraceRmiLaunchOffer offer) {
			super(plugin, offer);
		}

		@Override
		MenuData computeMenuData() {
			return new MenuData(
				prependMenuPath("Empty session ...", offer.getMenuPath()),
				offer.getIcon(), offer.getMenuGroup(), 0, offer.getMenuOrder());
		}

		@Override
		String getTopGroup(Program currentProgram) {
			return "2";
		}

		@Override
		String getTopOrder(Program currentProgram) {
			return "3";
		}
	}

	static abstract class AbstractReLaunchOfferAction extends AbstractLaunchOfferAction {
		public AbstractReLaunchOfferAction(TraceRmiLauncherServicePlugin plugin,
				TraceRmiLaunchOffer offer) {
			super(plugin, offer);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			plugin.relaunchOrConfigure(context, offer);
		}
	}

	static class TopReLaunchOfferAction extends AbstractReLaunchOfferAction {
		final Program program;

		public TopReLaunchOfferAction(TraceRmiLauncherServicePlugin plugin,
				TraceRmiLaunchOffer offer, Program program) {
			this.program = program;
			super(plugin, offer);
		}

		@Override
		MenuData computeMenuData() {
			String title = program == null
					? "Empty %s session".formatted(offer.getTitle())
					: "Re-launch %s in %s".formatted(getProgramName(program), offer.getTitle());
			return new MenuData(new String[] { title }, offer.getIcon(), "0: top");
		}

		@Override
		String getTopGroup(Program currentProgram) {
			return "0";
		}
	}

	static class ProgramReLaunchOfferAction extends AbstractReLaunchOfferAction {
		final Program program;

		public ProgramReLaunchOfferAction(TraceRmiLauncherServicePlugin plugin,
				TraceRmiLaunchOffer offer, Program program) {
			this.program = program;
			super(plugin, offer);
		}

		@Override
		MenuData computeMenuData() {
			return new MenuData(
				prependMenuPath("Re-launch %s ...".formatted(getProgramName(program)),
					offer.getMenuPath()),
				offer.getIcon(), offer.getMenuGroup(), 0, offer.getMenuOrder());
		}

		@Override
		String getTopGroup(Program currentProgram) {
			return "1";
		}

		@Override
		String getTopOrder(Program currentProgram) {
			return program == currentProgram ? "1" : "2";
		}
	}

	public void collectActionsForProgram(List<DockingActionIf> actions, Program program) {
		Collection<TraceRmiLaunchOffer> offers = plugin.getOffers(program);
		Map<String, Long> saved = plugin.loadSavedConfigs(program);
		for (TraceRmiLaunchOffer offer : offers) {
			if (program != null) {
				actions.add(new ProgramLaunchOfferAction(plugin, offer, program));
			}
			else if (!offer.requiresImage()) {
				actions.add(new EmptyLaunchOfferAction(plugin, offer));
			}
			Long last = saved.get(offer.getConfigName());
			if (last == null) {
				continue;
			}
			if (program != null) {
				actions.add(new ProgramReLaunchOfferAction(plugin, offer, program));
			}
		}
	}

	@Override
	public List<DockingActionIf> getActionList(ActionContext context) {
		ProgramManager programManager = plugin.getTool().getService(ProgramManager.class);
		List<Program> allPrograms = List.of(programManager.getAllOpenPrograms());
		List<DockingActionIf> actions = new ArrayList<>();
		for (Program program : allPrograms) {
			collectActionsForProgram(actions, program);
		}
		collectActionsForProgram(actions, null);
		ConfigLast last = plugin.findMostRecentConfig();
		TraceRmiLaunchOffer offer = plugin.findOffer(last);
		if (offer != null) {
			actions.add(new TopReLaunchOfferAction(plugin, offer, last.program()));
		}
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
				new MenuManager("Launch", (char) 0, GROUP, true, handler, groupMap);
			for (DockingActionIf action : actionList) {
				if (action instanceof AbstractLaunchOfferAction loa) {
					String[] path = action.getPopupMenuData().getMenuPath();
					String[] topPath = Arrays.copyOf(path, 1);
					groupMap.setMenuGroup(topPath,
						loa.getTopGroup(currentProgram),
						loa.getTopOrder(currentProgram));
				}
				action.setEnabled(action.isEnabledForContext(context));
				manager.addAction(action);
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
		// See comment on super method about use of runLater
		ConfigLast last = plugin.findMostRecentConfig();
		TraceRmiLaunchOffer offer = plugin.findOffer(last);
		if (offer == null) {
			Swing.runLater(() -> button.showPopup());
			return;
		}
		plugin.relaunchOrConfigure(context, offer);
	}

	@Override
	public String getDescription() {
		ConfigLast last = plugin.findMostRecentConfig();
		TraceRmiLaunchOffer offer = plugin.findOffer(last);
		if (offer == null) {
			return "Launch ...";
		}
		if (last.program() == null) {
			return "Empty %s session".formatted(offer.getTitle());
		}
		return "Re-launch %s in %s".formatted(getProgramName(last.program()), offer.getTitle());
	}
}

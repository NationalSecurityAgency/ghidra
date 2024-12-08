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
import docking.action.builder.ActionBuilder;
import docking.menu.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin.ConfigLast;
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

	protected String[] prependConfigAndLaunch(List<String> menuPath) {
		Program program = plugin.currentProgram;
		String title = program == null
				? "Configure and Launch ..."
				: "Configure and Launch %s using...".formatted(getProgramName(program));
		return Stream.concat(Stream.of(title), menuPath.stream()).toArray(String[]::new);
	}

	@Override
	public List<DockingActionIf> getActionList(ActionContext context) {
		Program program = plugin.currentProgram;
		Collection<TraceRmiLaunchOffer> offers = plugin.getOffers(program);

		List<DockingActionIf> actions = new ArrayList<>();

		Map<String, Long> saved = plugin.loadSavedConfigs(program);

		for (TraceRmiLaunchOffer offer : offers) {
			actions.add(new ActionBuilder(offer.getConfigName(), plugin.getName())
					.popupMenuPath(prependConfigAndLaunch(offer.getMenuPath()))
					.popupMenuGroup(offer.getMenuGroup(), offer.getMenuOrder())
					.popupMenuIcon(offer.getIcon())
					.helpLocation(offer.getHelpLocation())
					.enabledWhen(ctx -> !offer.requiresImage() || program != null)
					.onAction(ctx -> plugin.configureAndLaunch(offer))
					.build());
			Long last = saved.get(offer.getConfigName());
			if (last == null) {
				// NB. If program == null, this will always happen.
				// Thus, no worries about getProgramName(program) below.
				continue;
			}
			String title = program == null
					? "Re-launch " + offer.getTitle()
					: "Re-launch %s using %s".formatted(getProgramName(program), offer.getTitle());
			actions.add(new ActionBuilder(offer.getConfigName(), plugin.getName())
					.popupMenuPath(title)
					.popupMenuGroup("0", "%016x".formatted(Long.MAX_VALUE - last))
					.popupMenuIcon(offer.getIcon())
					.helpLocation(offer.getHelpLocation())
					.enabledWhen(ctx -> true)
					.onAction(ctx -> plugin.relaunch(offer))
					.build());
		}
		return actions;
	}

	class MenuActionDockingToolbarButton extends MultipleActionDockingToolbarButton {
		public MenuActionDockingToolbarButton(MultiActionDockingActionIf action) {
			super(action);
		}

		@Override
		protected JPopupMenu doCreateMenu() {
			ActionContext context = getActionContext();
			List<DockingActionIf> actionList = getActionList(context);
			MenuHandler handler =
				new PopupMenuHandler(plugin.getTool().getWindowManager(), context);
			MenuManager manager =
				new MenuManager("Launch", (char) 0, GROUP, true, handler, null);
			for (DockingActionIf action : actionList) {
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
		return !plugin.getOffers(plugin.currentProgram).isEmpty();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// See comment on super method about use of runLater
		ConfigLast last = plugin.findMostRecentConfig(plugin.currentProgram);
		TraceRmiLaunchOffer offer = plugin.findOffer(last);
		if (offer == null) {
			Swing.runLater(() -> button.showPopup());
			return;
		}
		plugin.relaunch(offer);
	}

	@Override
	public String getDescription() {
		Program program = plugin.currentProgram;
		ConfigLast last = plugin.findMostRecentConfig(program);
		TraceRmiLaunchOffer offer = plugin.findOffer(last);
		if (offer == null && program == null) {
			return "Configure and launch";
		}
		if (offer == null) {
			return "Configure and launch " + getProgramName(program);
		}
		if (program == null) {
			return "Re-launch " + offer.getTitle();
		}
		return "Re-launch %s using %s".formatted(getProgramName(program), offer.getTitle());
	}
}

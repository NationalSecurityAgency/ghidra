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

import java.io.IOException;
import java.util.*;
import java.util.stream.Stream;

import javax.swing.*;

import org.jdom.Element;
import org.jdom.JDOMException;

import docking.ActionContext;
import docking.PopupMenuHandler;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.menu.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.framework.options.SaveState;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.util.*;
import ghidra.util.xml.XmlUtilities;

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
		return Stream.concat(
			Stream.of("Configure and Launch " + program.getName() + " using..."),
			menuPath.stream()).toArray(String[]::new);
	}

	record ConfigLast(String configName, long last) {
	}

	ConfigLast checkSavedConfig(ProgramUserData userData, String propName) {
		if (!propName.startsWith(AbstractTraceRmiLaunchOffer.PREFIX_DBGLAUNCH)) {
			return null;
		}
		String configName =
			propName.substring(AbstractTraceRmiLaunchOffer.PREFIX_DBGLAUNCH.length());
		String propVal = Objects.requireNonNull(
			userData.getStringProperty(propName, null));
		Element element;
		try {
			element = XmlUtilities.fromString(propVal);
		}
		catch (JDOMException | IOException e) {
			Msg.error(this, "Could not load launcher config for " + configName + ": " + e, e);
			return null;
		}
		SaveState state = new SaveState(element);
		if (!state.hasValue("last")) {
			return null;
		}
		return new ConfigLast(configName, state.getLong("last", 0));
	}

	ConfigLast findMostRecentConfig() {
		Program program = plugin.currentProgram;
		if (program == null) {
			return null;
		}
		ConfigLast best = null;

		ProgramUserData userData = program.getProgramUserData();
		for (String propName : userData.getStringPropertyNames()) {
			ConfigLast candidate = checkSavedConfig(userData, propName);
			if (candidate == null) {
				continue;
			}
			else if (best == null) {
				best = candidate;
			}
			else if (candidate.last > best.last) {
				best = candidate;
			}
		}
		return best;
	}

	@Override
	public List<DockingActionIf> getActionList(ActionContext context) {
		Program program = plugin.currentProgram;
		Collection<TraceRmiLaunchOffer> offers = plugin.getOffers(program);

		List<DockingActionIf> actions = new ArrayList<>();

		Map<String, Long> saved = new HashMap<>();
		if (program != null) {
			ProgramUserData userData = program.getProgramUserData();
			for (String propName : userData.getStringPropertyNames()) {
				ConfigLast check = checkSavedConfig(userData, propName);
				if (check == null) {
					continue;
				}
				saved.put(check.configName, check.last);
			}
		}

		for (TraceRmiLaunchOffer offer : offers) {
			actions.add(new ActionBuilder(offer.getConfigName(), plugin.getName())
					.popupMenuPath(prependConfigAndLaunch(offer.getMenuPath()))
					.popupMenuGroup(offer.getMenuGroup(), offer.getMenuOrder())
					.popupMenuIcon(offer.getIcon())
					.helpLocation(offer.getHelpLocation())
					.enabledWhen(ctx -> true)
					.onAction(ctx -> plugin.configureAndLaunch(offer))
					.build());
			Long last = saved.get(offer.getConfigName());
			if (last == null) {
				// NB. If program == null, this will always happen.
				// Thus, no worries about program.getName() below.
				continue;
			}
			actions.add(new ActionBuilder(offer.getConfigName(), plugin.getName())
					.popupMenuPath("Re-launch " + program.getName() + " using " + offer.getTitle())
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
		return plugin.currentProgram != null;
	}

	protected TraceRmiLaunchOffer findOffer(ConfigLast last) {
		if (last == null) {
			return null;
		}
		for (TraceRmiLaunchOffer offer : plugin.getOffers(plugin.currentProgram)) {
			if (offer.getConfigName().equals(last.configName)) {
				return offer;
			}
		}
		return null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// See comment on super method about use of runLater
		ConfigLast last = findMostRecentConfig();
		TraceRmiLaunchOffer offer = findOffer(last);
		if (offer == null) {
			Swing.runLater(() -> button.showPopup());
			return;
		}
		plugin.relaunch(offer);
	}

	@Override
	public String getDescription() {
		Program program = plugin.currentProgram;
		if (program == null) {
			return "Launch (program required)";
		}
		ConfigLast last = findMostRecentConfig();
		TraceRmiLaunchOffer offer = findOffer(last);
		if (last == null) {
			return "Configure and launch " + program.getName();
		}
		return "Re-launch " + program.getName() + " using " + offer.getTitle();
	}
}

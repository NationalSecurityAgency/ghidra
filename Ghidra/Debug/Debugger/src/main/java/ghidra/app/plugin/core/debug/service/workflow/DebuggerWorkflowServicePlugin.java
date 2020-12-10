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
package ghidra.app.plugin.core.debug.service.workflow;

import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceOpenedPluginEvent;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.*;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.framework.main.FrontEndOnly;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.AutoService.Wiring;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginEventListener;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.CollectionChangeListener;

@PluginInfo( //
		shortDescription = "Debugger workflow service", //
		description = "Manage automatic debugging actions and analysis", //
		category = PluginCategoryNames.DEBUGGER, //
		packageName = DebuggerPluginPackage.NAME, //
		status = PluginStatus.RELEASED, //
		servicesProvided = { //
			DebuggerWorkflowService.class, //
		} //
)
public class DebuggerWorkflowServicePlugin extends Plugin
		implements DebuggerWorkflowService, FrontEndOnly, OptionsChangeListener {

	protected class ForBotsModelsChangeListener
			implements CollectionChangeListener<DebuggerObjectModel> {
		@Override
		public void elementAdded(DebuggerObjectModel element) {
			dispatch(a -> a.modelAdded(element));
		}

		@Override
		public void elementRemoved(DebuggerObjectModel element) {
			dispatch(a -> a.modelRemoved(element));
		}
	}

	protected class ForTrackingOpenStuffPluginEventListener implements PluginEventListener {
		private final PluginTool t;

		// TODO: Determine interest dynamically, based on bots' overrides
		private final Set<Class<? extends PluginEvent>> types = Set.of(
			ProgramOpenedPluginEvent.class,
			ProgramClosedPluginEvent.class,
			TraceOpenedPluginEvent.class,
			TraceClosedPluginEvent.class //
		);

		public ForTrackingOpenStuffPluginEventListener(PluginTool tool) {
			this.t = tool;

			for (Class<? extends PluginEvent> cls : types) {
				tool.addEventListener(cls, this);
			}
		}

		private void dispose() {
			for (Class<? extends PluginEvent> cls : types) {
				t.removeEventListener(cls, this);
			}
		}

		@Override
		public void eventSent(PluginEvent event) {
			if (event instanceof ProgramOpenedPluginEvent) {
				ProgramOpenedPluginEvent evt = (ProgramOpenedPluginEvent) event;
				dispatch(a -> a.programOpened(t, evt.getProgram()));
			}
			if (event instanceof ProgramClosedPluginEvent) {
				ProgramClosedPluginEvent evt = (ProgramClosedPluginEvent) event;
				dispatch(a -> a.programClosed(t, evt.getProgram()));
			}
			if (event instanceof TraceOpenedPluginEvent) {
				TraceOpenedPluginEvent evt = (TraceOpenedPluginEvent) event;
				dispatch(a -> a.traceOpened(t, evt.getTrace()));
			}
			if (event instanceof TraceClosedPluginEvent) {
				TraceClosedPluginEvent evt = (TraceClosedPluginEvent) event;
				dispatch(a -> a.traceClosed(t, evt.getTrace()));
			}
		}
	}

	// @AutoServiceConsumed via method
	private DebuggerModelService modelService;
	@SuppressWarnings("unused")
	private Wiring autoServiceWiring;

	private final ChangeListener botsChangeListener = this::botsChanged;
	private final Map<PluginTool, ForTrackingOpenStuffPluginEventListener> trackStuffListenersByTool =
		new HashMap<>();

	/* testing */ final List<DebuggerBot> allBots = new ArrayList<>();

	// Cannot auto-wire, since they're dynamically populated
	private final ToolOptions options;

	@SuppressWarnings("hiding") // I'm FrontEndOnly
	protected final FrontEndTool tool;
	private ForBotsModelsChangeListener modelsChangedListener =
		new ForBotsModelsChangeListener();

	public DebuggerWorkflowServicePlugin(PluginTool tool) {
		super(tool);
		this.tool = (FrontEndTool) tool; // I'm FrontEndOnly

		this.autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
		this.options = tool.getOptions(DebuggerResources.OPTIONS_CATEGORY_WORKFLOW);
		this.options.addOptionsChangeListener(this);

	}

	@Override
	protected void init() {
		super.init();

		ClassSearcher.addChangeListener(botsChangeListener);
		refreshBots();

		/**
		 * Note instead of trying to use the tool manager to track running tools -- which rests
		 * precariously upon the project, anyway -- we will have the proxy plugin notify the
		 * front-end plugin of a new tool. This actually works better, since we should affect only
		 * those plugin tools which have the proxy plugin enabled.
		 */
	}

	@Override
	protected void dispose() {
		ClassSearcher.removeChangeListener(botsChangeListener);

		// TODO: Is there a good way to clean up the proxies?
		// What if other plugins come to depend on it?
		synchronized (trackStuffListenersByTool) {
			for (ForTrackingOpenStuffPluginEventListener l : trackStuffListenersByTool.values()) {
				l.dispose();
			}
			trackStuffListenersByTool.clear();
		}
	}

	private void dispatch(Consumer<DebuggerBot> evt) {
		synchronized (allBots) {
			for (DebuggerBot bot : allBots) {
				if (bot.isEnabled()) {
					evt.accept(bot);
				}
			}
		}
	}

	private void botsChanged(ChangeEvent evt) {
		refreshBots();
	}

	private void refreshBots() {
		synchronized (allBots) {
			List<DebuggerBot> removed = new ArrayList<>(allBots);
			allBots.clear();
			allBots.addAll(ClassSearcher.getInstances(DebuggerBot.class));
			List<DebuggerBot> added = new ArrayList<>(allBots);
			added.removeAll(removed);
			removed.removeAll(allBots);

			for (DebuggerBot bot : removed) {
				options.removeOption(bot.getDescription());
			}

			for (DebuggerBot bot : added) {
				options.registerOption(bot.getDescription(), OptionType.BOOLEAN_TYPE,
					bot.isEnabledByDefault(), bot.getHelpLocation(), bot.getDetails());
			}

			for (DebuggerBot bot : removed) {
				try {
					if (bot.isEnabled()) {
						bot.disable();
					}
				}
				catch (Throwable t) {
					Msg.error(this, "Failed to disable debugger bot: " + bot, t);
				}
			}

			// Require explicit enable via API during testing. These tend to get in the way.
			if (SystemUtilities.isInTestingMode()) {
				return;
			}
			// TODO: Remember bot enablement in tool config
			for (DebuggerBot bot : added) {
				try {
					boolean enabled = options.getBoolean(bot.getDescription(),
						bot.isEnabledByDefault());
					bot.setEnabled(this, enabled);
				}
				catch (Throwable t) {
					Msg.error(this, "Failed to enable debugger bot: " + bot, t);
				}
			}
		}
	}

	@Override
	public void optionsChanged(ToolOptions opts, String optionName, Object oldValue,
			Object newValue) {
		assert options == opts;
		// Not the most efficient, but there are few, and this should occur infrequently

		// Require explicit enable via API during testing. These tend to get in the way.
		if (SystemUtilities.isInTestingMode()) {
			return;
		}
		synchronized (allBots) {
			for (DebuggerBot bot : allBots) {
				if (!optionName.equals(bot.getDescription())) {
					continue;
				}
				boolean enabled = (Boolean) newValue;
				if (bot.isEnabled() != enabled) {
					bot.setEnabled(this, enabled);
				}
			}
		}
	}

	public void pluginToolAdded(PluginTool t) {
		trackToolEvents(t);
	}

	public void pluginToolRemoved(PluginTool t) {
		untrackToolEvents(t);
	}

	private void trackToolEvents(PluginTool t) {
		synchronized (trackStuffListenersByTool) {
			ForTrackingOpenStuffPluginEventListener old =
				trackStuffListenersByTool.put(t, new ForTrackingOpenStuffPluginEventListener(t));
			if (old != null) {
				old.dispose();
				Msg.warn(this, "Tracking a tool twice: " + tool);
			}
		}
	}

	private void untrackToolEvents(PluginTool t) {
		synchronized (trackStuffListenersByTool) {
			ForTrackingOpenStuffPluginEventListener removed = trackStuffListenersByTool.remove(t);
			if (removed != null) {
				removed.dispose();
			}
			else {
				Msg.warn(this, "Never tracked a tool: " + tool);
			}
		}
	}

	public Collection<PluginTool> getProxyingPluginTools() {
		synchronized (trackStuffListenersByTool) {
			return List.copyOf(trackStuffListenersByTool.keySet());
		}
	}

	@AutoServiceConsumed
	private void setModelService(DebuggerModelService modelService) {
		if (this.modelService != null) {
			this.modelService.removeModelsChangedListener(modelsChangedListener);
		}
		this.modelService = modelService;
		if (this.modelService != null) {
			this.modelService.addModelsChangedListener(modelsChangedListener);
		}
		// TODO: Invoke models removed/added
	}

	@Override
	public Set<DebuggerBot> getAllBots() {
		synchronized (allBots) {
			return Set.copyOf(allBots);
		}
	}

	@Override
	public Set<DebuggerBot> getEnabledBots() {
		synchronized (allBots) {
			return allBots.stream().filter(a -> a.isEnabled()).collect(Collectors.toSet());
		}
	}

	@Override
	public Set<DebuggerBot> getDisabledBots() {
		synchronized (allBots) {
			return allBots.stream().filter(a -> !a.isEnabled()).collect(Collectors.toSet());
		}
	}

	@Override
	public void enableBots(Set<DebuggerBot> bots) {
		synchronized (allBots) {
			for (DebuggerBot bot : bots) {
				if (!allBots.contains(bot)) {
					Msg.error(this, "Ignoring request to enable non-discoverable bot " + bot);
					continue;
				}
				if (!bot.isEnabled()) {
					try {
						bot.enable(this);
					}
					catch (Throwable e) {
						Msg.error(this, "Error enabling " + bot, e);
					}
				}
			}
		}
	}

	@Override
	public void disableBots(Set<DebuggerBot> bots) {
		synchronized (allBots) {
			for (DebuggerBot bot : bots) {
				if (!allBots.contains(bot)) {
					Msg.error(this, "Ignoring request to disable non-discoverable bot " + bot);
					continue;
				}
				if (bot.isEnabled()) {
					try {
						bot.disable();
					}
					catch (Throwable e) {
						Msg.error(this, "Error disabling " + bot, e);
					}
				}
			}
		}
	}
}

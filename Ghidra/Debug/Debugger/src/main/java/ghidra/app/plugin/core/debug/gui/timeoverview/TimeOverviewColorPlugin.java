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
package ghidra.app.plugin.core.debug.gui.timeoverview;

import java.util.*;
import java.util.stream.Collectors;

import javax.swing.SwingUtilities;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import docking.ActionContext;
import docking.action.*;
import docking.menu.MultiActionDockingAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.timeoverview.timetype.TimeType;
import ghidra.app.services.DebuggerListingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.bookmark.TraceBookmark;
import ghidra.trace.model.bookmark.TraceBookmarkManager;
import ghidra.trace.model.breakpoint.TraceBreakpointLocation;
import ghidra.trace.model.breakpoint.TraceBreakpointManager;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceModuleManager;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import resources.ResourceManager;

/**
 * Plugin to manage {@link TimeOverviewColorService}s. It creates actions for each service and
 * installs and removes {@link TimeOverviewColorComponent} as indicated by the action.
 */

@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = DebuggerPluginPackage.NAME,
	category = PluginCategoryNames.DEBUGGER,
	shortDescription = "Time Overview Color Manager",
	description = "Provides various color mappings for the trace snap space.",
	eventsConsumed = {
		TraceOpenedPluginEvent.class, //
		TraceClosedPluginEvent.class, //
		TraceActivatedPluginEvent.class, //
	}, //
	servicesRequired = { //
		DebuggerTraceManagerService.class, //
	} // 
)

public class TimeOverviewColorPlugin extends AbstractDebuggerPlugin {

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerListingService listingService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	public static final String HELP_TOPIC = "OverviewPlugin";
	private static final String ACTIVE_SERVICES = "ActiveServices";
	private List<TimeOverviewColorService> allServices;
	private Map<TimeOverviewColorService, TimeOverviewColorComponent> activeServices =
		new LinkedHashMap<>(); // maintain the left to right order of the active overview bars.
	private Map<TimeOverviewColorService, OverviewToggleAction> actionMap = new HashMap<>();
	private MultiActionDockingAction multiAction;

	private Trace currentTrace;
	private final TimeOverviewEventListener eventListener = new TimeOverviewEventListener(this);
	private Map<Trace, TreeSet<Long>> sets = new WeakHashMap<>();
	private Map<Long, Set<Pair<TimeType, String>>> types = new HashMap<>();
	private long LMAX = Lifespan.ALL.lmax();

	public TimeOverviewColorPlugin(PluginTool tool) {
		super(tool);
		autoServiceWiring = AutoService.wireServicesConsumed(tool, this);
	}

	@Override
	protected void init() {
		super.init();
		allServices = ClassSearcher.getInstances(TimeOverviewColorService.class);
		createActions();
		for (TimeOverviewColorService service : allServices) {
			service.initialize(tool);
		}
	}

	@Override
	public void readConfigState(SaveState saveState) {
		String[] activeServiceNames = saveState.getStrings(ACTIVE_SERVICES, new String[0]);
		for (String serviceName : activeServiceNames) {
			TimeOverviewColorService service = getService(serviceName);
			if (service == null) {
				Msg.warn(this, "Can't restore TimeOverviewColorService: " + serviceName);
				continue;
			}
			OverviewToggleAction action = actionMap.get(service);
			action.setSelected(true);
			// do this later so that they show up to the left of the standard marker service overview.
			SwingUtilities.invokeLater(() -> installOverview(service));
		}
	}

	private TimeOverviewColorService getService(String serviceName) {
		for (TimeOverviewColorService service : allServices) {
			if (service.getName().equals(serviceName)) {
				return service;
			}
		}
		return null;
	}

	@Override
	protected void cleanup() {

		List<TimeOverviewColorService> services = new ArrayList<>(activeServices.keySet());
		for (TimeOverviewColorService service : services) {
			uninstallOverview(service);
		}
		listingService.removeLocalAction(multiAction);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		saveState.putStrings(ACTIVE_SERVICES, getActiveServiceNames());
	}

	private String[] getActiveServiceNames() {
		List<String> names =
			activeServices.keySet().stream().map(s -> s.getName()).collect(Collectors.toList());

		return names.toArray(new String[names.size()]);
	}

	private void createActions() {
		for (TimeOverviewColorService overviewColorService : allServices) {
			actionMap.put(overviewColorService,
				new OverviewToggleAction(getName(), overviewColorService));
		}
		multiAction = new MultiActionDockingAction("TimeOverview", getName());
		//multiAction.setPerformActionOnButtonClick(false);
		multiAction.setActions(new ArrayList<DockingActionIf>(actionMap.values()));
		multiAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/x-office-document-template.png")));
		listingService.addLocalAction(multiAction);
		multiAction.setDescription("Toggles trace overview margin displays.");
		multiAction.setHelpLocation(
			new HelpLocation(TimeOverviewColorPlugin.HELP_TOPIC,
				TimeOverviewColorPlugin.HELP_TOPIC));

	}

	private class OverviewToggleAction extends ToggleDockingAction {

		private TimeOverviewColorService service;

		public OverviewToggleAction(String owner, TimeOverviewColorService service) {
			super(service.getName(), owner);
			this.service = service;
			setMenuBarData(new MenuData(new String[] { "Show " + service.getName() }));
			setHelpLocation(service.getHelpLocation());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (isSelected()) {
				installOverview(service);
			}
			else {
				uninstallOverview(service);
			}
		}

	}

	/**
	 * Installs the given {@link TimeOverviewColorService} into the Listing margin bars. This is
	 * public only for testing and screenshot purposes.
	 * 
	 * @param overviewColorService the service to display colors in the Listing's margin bars.
	 */
	public void installOverview(TimeOverviewColorService overviewColorService) {
		overviewColorService.setTrace(currentTrace);
		TimeOverviewColorComponent overview =
			new TimeOverviewColorComponent(tool, overviewColorService);
		activeServices.put(overviewColorService, overview);
		listingService.addOverviewProvider(overview);
		overview.installActions();
		overview.setPlugin(this);
	}

	private void uninstallOverview(TimeOverviewColorService overviewColorService) {
		TimeOverviewColorComponent overviewComponent = activeServices.get(overviewColorService);
		overviewComponent.uninstallActions();
		listingService.removeOverviewProvider(overviewComponent);
		activeServices.remove(overviewColorService);
		overviewColorService.setTrace(null);
	}

	protected void traceActivated(Trace trace) {
		if (trace != null && trace != currentTrace) {
			if (currentTrace != null) {
				currentTrace.removeListener(eventListener);
			}
			currentTrace = trace;
			currentTrace.addListener(eventListener);
			for (TimeOverviewColorService service : activeServices.keySet()) {
				service.setTrace(trace);
			}
			updateMap();
		}
	}

	protected void traceDeactivated(Trace trace) {
		if (trace == currentTrace) {
			currentTrace.removeListener(eventListener);
			currentTrace = null;
			for (TimeOverviewColorService service : activeServices.keySet()) {
				service.setTrace(null);
			}
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent ev) {
			DebuggerCoordinates coordinates = ev.getActiveCoordinates();
			traceActivated(coordinates.getTrace());
			eventListener.coordinatesActivated(coordinates);
		}
		else if (event instanceof TraceClosedPluginEvent ev) {
			Trace trace = ev.getTrace();
			if (trace == currentTrace) {
				sets.remove(trace);
				traceDeactivated(trace);
			}
		}
	}

	void updateMap() {
		TreeSet<Long> set = new TreeSet<>();
		Trace trace = traceManager.getCurrentTrace();
		TraceThreadManager threadManager = trace.getThreadManager();
		for (TraceThread thread : threadManager.getAllThreads()) {
			addObject(set, thread.getObject());
		}
		TraceModuleManager moduleManager = trace.getModuleManager();
		for (TraceModule module : moduleManager.getAllModules()) {
			addObject(set, module.getObject());
		}
		TraceMemoryManager memoryManager = trace.getMemoryManager();
		for (TraceMemoryRegion region : memoryManager.getAllRegions()) {
			addObject(set, region.getObject());
		}
		TraceBreakpointManager breakpointManager = trace.getBreakpointManager();
		for (TraceBreakpointLocation bpt : breakpointManager.getAllBreakpointLocations()) {
			addObject(set, bpt.getObject());
		}
		TraceBookmarkManager bookmarkManager = trace.getBookmarkManager();
		for (TraceBookmark mark : bookmarkManager.getAllBookmarks()) {
			Lifespan span = mark.getLifespan();
			set.add(span.min());
			if (span.lmax() == LMAX) {
				set.add(span.max());
			}
		}
		for (TimeOverviewColorComponent provider : activeServices.values()) {
			provider.setLifeSet(set);
		}
	}

	private void addObject(TreeSet<Long> set, TraceObject obj) {
		for (Lifespan span : obj.getLife().spans()) {
			set.add(span.min());
			if (span.lmax() == LMAX) {
				set.add(span.max());
			}
		}
	}

	void updateMap(long offset, TimeType type, String desc, boolean override) {
		TreeSet<Long> set = getLifeSet();
		if (!override && set.contains(offset)) {
			return;
		}
		if (offset == LMAX) {
			return;
		}
		set.add(offset);
		setLifespanType(offset, type, desc);
		for (TimeOverviewColorComponent provider : activeServices.values()) {
			provider.setLifeSet(set);
		}
	}

	TreeSet<Long> getLifeSet() {
		TreeSet<Long> set = sets.get(currentTrace);
		if (set == null) {
			set = new TreeSet<>();
			sets.put(currentTrace, set);
		}
		return set;
	}

	/**
	 * Determines the {@link TimeType} for the given offset
	 *
	 * @param offset the offset for which to get an LifespanType.
	 * @return the {@link TimeType} for the given offset.
	 */
	public Set<Pair<TimeType, String>> getTypes(Long offset) {
		Set<Pair<TimeType, String>> set = types.get(offset);
		if (set == null) {
			set = new HashSet<>();
		}
		return set;
	}

	void setLifespanType(Long offset, TimeType type, String desc) {
		Set<Pair<TimeType, String>> set = getTypes(offset);
		set.add(new ImmutablePair<TimeType, String>(type, desc));
		types.put(offset, set);
	}

	public void gotoSnap(Long offset) {
		if (offset == null) {
			offset = 0L;
		}
		traceManager.activateSnap(offset);
	}

	public void setLifespan(Lifespan span) {
		for (TimeOverviewColorComponent provider : activeServices.values()) {
			provider.setLifespan(span);
		}
	}

}

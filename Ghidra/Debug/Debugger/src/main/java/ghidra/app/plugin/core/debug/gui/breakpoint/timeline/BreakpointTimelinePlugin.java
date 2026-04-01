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
package ghidra.app.plugin.core.debug.gui.breakpoint.timeline;

import java.util.*;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.trace.model.Trace;

@PluginInfo(
	shortDescription = "Debugger breakpoint hit timeline",
	description = "Timeline of all snapshots showing breakpoint hits",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.UNSTABLE,
	servicesRequired = { DebuggerTraceManagerService.class, },
	eventsConsumed = { TraceClosedPluginEvent.class, TraceActivatedPluginEvent.class, }
)
public class BreakpointTimelinePlugin extends AbstractDebuggerPlugin {
	BreakpointTimelineProvider provider;
	private Trace currentTrace;

	private final Map<Trace, List<BreakpointTimelineProvider>> traceSpecificZoomProviders =
		new HashMap<>();

	public BreakpointTimelinePlugin(PluginTool tool) {
		super(tool);
	}

	void createZoomProvider(String title, long start, long stop) {
		traceSpecificZoomProviders.computeIfAbsent(currentTrace, k -> new ArrayList<>())
				.add(new BreakpointTimelineProvider(provider, title, start, stop));
	}

	@Override
	protected void dispose() {
		for (final var providers : traceSpecificZoomProviders.values()) {
			for (final var provider : providers) {
				tool.removeComponentProvider(provider);
			}
		}
		tool.removeComponentProvider(provider);
		super.dispose();
	}

	private void hideZoomProviders(Trace t) {
		final List<BreakpointTimelineProvider> zoomProviders = traceSpecificZoomProviders.get(t);
		if (zoomProviders != null) {
			for (final BreakpointTimelineProvider p : zoomProviders) {
				tool.showComponentProvider(p, false);
			}
		}
	}

	@Override
	protected void init() {
		super.init();
		provider = new BreakpointTimelineProvider(this);
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		switch (event) {
			case final TraceClosedPluginEvent evt -> {
				final Trace t = evt.getTrace();

				if (currentTrace == t) {
					currentTrace = null;
					provider.setTrace(null);
				}
				removeZoomProviders(t);
			}
			case final TraceActivatedPluginEvent evt -> {
				final Trace t = evt.getActiveCoordinates().getTrace();
				if (t == null) {
					provider.setTrace(null);
				}
				else if (currentTrace != t) {
					hideZoomProviders(currentTrace);
					currentTrace = t;
					provider.setTrace(currentTrace);
					showZoomProviders(currentTrace);
				}
				else {
					refreshAllProviders(null);
				}
			}
			default -> {
			}
		}
	}

	void refreshAllProviders(BreakpointTimelineProvider currentProvider) {
		final List<BreakpointTimelineProvider> zoomProviders =
			traceSpecificZoomProviders.get(currentTrace);
		if (zoomProviders != null) {
			for (final BreakpointTimelineProvider p : zoomProviders) {
				if (p != currentProvider) {
					p.refresh();
				}
			}
		}

		if (provider != currentProvider) {
			provider.refresh();
		}
	}

	void removeZoomProviders(Trace t) {
		final List<BreakpointTimelineProvider> zoomProviders = traceSpecificZoomProviders.remove(t);
		if (zoomProviders != null) {
			for (final BreakpointTimelineProvider p : zoomProviders) {
				tool.removeComponentProvider(p);
			}
		}
	}

	private void showZoomProviders(Trace t) {
		final List<BreakpointTimelineProvider> zoomProviders = traceSpecificZoomProviders.get(t);
		if (zoomProviders != null) {
			for (final BreakpointTimelineProvider p : zoomProviders) {
				tool.showComponentProvider(p, true);
			}
		}
	}
}

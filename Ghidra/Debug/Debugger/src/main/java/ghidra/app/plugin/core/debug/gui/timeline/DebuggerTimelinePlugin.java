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
package ghidra.app.plugin.core.debug.gui.timeline;

import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.gui.objects.ObjectUpdatedEvent;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Program;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.Trace;

@PluginInfo( //
		shortDescription = "Debugger timeline manager", //
		description = "GUI to view object timelines", //
		category = PluginCategoryNames.DEBUGGER, //
		packageName = DebuggerPluginPackage.NAME, //
		status = PluginStatus.UNSTABLE, //
		eventsConsumed = { //
			ProgramOpenedPluginEvent.class, // TODO: Remove?
			ProgramSelectionPluginEvent.class, // TODO: Later or remove
			ProgramHighlightPluginEvent.class, // TODO: Later or remove
			ProgramActivatedPluginEvent.class, // TODO: Remove? Covered by Location?
			ProgramClosedPluginEvent.class, // For marker set cleanup
			ProgramLocationPluginEvent.class, // For static listing sync
			TraceActivatedPluginEvent.class, //
			ObjectUpdatedEvent.class, //
		}, //
		servicesRequired = { //
			DebuggerTraceManagerService.class, //
		} // 
)

public class DebuggerTimelinePlugin extends AbstractDebuggerPlugin {
	protected DebuggerTimelineProvider provider;
	private Program currentProgram;
	private Map<Program, Trace> traceMap = new LinkedHashMap<>();

	public DebuggerTimelinePlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		provider = new DebuggerTimelineProvider(this);
		super.init();
	}

	@Override
	protected void dispose() {
		tool.removeComponentProvider(provider);
		super.dispose();
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof ProgramOpenedPluginEvent) {
			setProgram(((ProgramOpenedPluginEvent) event).getProgram(), false);
		}
		if (event instanceof ProgramActivatedPluginEvent) {
			setProgram(((ProgramActivatedPluginEvent) event).getActiveProgram(), false);
		}
		if (event instanceof ProgramClosedPluginEvent) {
			setProgram(((ProgramClosedPluginEvent) event).getProgram(), true);
		}
		if (event instanceof ObjectUpdatedEvent) {
			provider.update(((ObjectUpdatedEvent) event).getObject());
		}
		if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent ev = (TraceActivatedPluginEvent) event;
			provider.coordinatesActivated(ev.getActiveCoordinates());
		}
	}

	private void setProgram(Program pgm, boolean remove) {
		currentProgram = pgm;
		if (pgm == null) {
			return;
		}
		try {
			Trace trace = null;
			if (traceMap.containsKey(pgm)) {
				trace = traceMap.get(pgm);
				if (remove) {
					traceMap.remove(pgm);
					trace = null;
				}
			}
			else {
				// TODO: I'm not sure what this is doing, but it seems like a bad idea....
				CompilerSpec cspec = pgm.getCompilerSpec();
				trace = new DBTrace(pgm.getName(), cspec, this);
			}
			// TODO: Nothing seems to put into traceMap, so just commenting out
			// provider.doSetTrace(trace);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}

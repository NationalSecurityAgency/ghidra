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
package ghidra.app.plugin.core.debug.gui.internal;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.Trace;

@PluginInfo(
	shortDescription = "Plot R*-Trees",
	description = "Plot R*-Trees in Trace Databases",
	category = PluginCategoryNames.DIAGNOSTIC,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.STABLE,
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
	})
public class RStarDiagnosticsPlugin extends Plugin {
	static final int INITIAL_DEPTH = 3;
	static final int MIN_DEPTH = 1;

	protected final RStarPlotProvider plotProvider;
	protected final RStarTreeProvider treeProvider;
	protected DebuggerCoordinates current;
	protected DBTraceMemorySpace space;

	public RStarDiagnosticsPlugin(PluginTool tool) {
		super(tool);
		plotProvider = new RStarPlotProvider(this);
		treeProvider = new RStarTreeProvider(this);
	}

	@Override
	protected void init() {
		super.init();
		tool.addComponentProvider(plotProvider, true);
		tool.addComponentProvider(treeProvider, true);
	}

	@Override
	protected void dispose() {
		tool.removeComponentProvider(plotProvider);
		super.dispose();
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent ev) {
			coordinatesActivated(ev.getActiveCoordinates());
		}
	}

	protected DBTraceMemorySpace computeSpace() {
		Trace trace = current.getTrace();
		if (trace == null) {
			return null;
		}
		if (!(trace.getMemoryManager() instanceof DBTraceMemoryManager mem)) {
			return null;
		}
		return mem.getMemorySpace(trace.getBaseAddressFactory().getDefaultAddressSpace(), false);
	}

	protected void coordinatesActivated(DebuggerCoordinates current) {
		this.current = current;
		this.space = computeSpace();
		if (space == null) {
			plotProvider.bounds = null;
		}
		plotProvider.component.repaint();
		treeProvider.refresh();
	}
}

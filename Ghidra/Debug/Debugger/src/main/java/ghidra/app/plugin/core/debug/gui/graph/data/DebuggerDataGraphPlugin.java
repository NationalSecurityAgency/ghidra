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
package ghidra.app.plugin.core.debug.gui.graph.data;

import datagraph.AbstractDataGraphPlugin;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceLocationPluginEvent;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;

/**
 * Plugin for showing a graph of data from the listing.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = DebuggerPluginPackage.NAME,
	category = PluginCategoryNames.DEBUGGER,
	shortDescription = "Debugger Data Graph",
	description = """
		Plugin for displaying graphs of data objects in memory. From any data object in the
		listing, the user can display a graph of that data object. Initially, a graph will be shown
		with one vertex that has a scrollable view of the values in memory associated with that data. 
		Also, any pointers or references from or to that data can be explored by following the
		references and creating additional vertices for the referenced code or data.
	""",
	eventsConsumed = {
		TraceLocationPluginEvent.class, 
	},
	eventsProduced = {
		TraceLocationPluginEvent.class, 
	}
)
//@formatter:on
public class DebuggerDataGraphPlugin extends AbstractDataGraphPlugin {
	public DebuggerDataGraphPlugin(PluginTool plugintool) {
		super(plugintool);
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof TraceLocationPluginEvent ev) {
			ProgramLocation location = ev.getLocation();
			goTo(location);
		}
	}

	@Override
	public void fireLocationEvent(ProgramLocation location) {
		firePluginEvent(new TraceLocationPluginEvent(getName(), location));
	}

	@Override
	protected boolean isGraphActionEnabled(ListingActionContext context) {
		if (!context.getNavigatable().isDynamic()) {
			return false;
		}
		return super.isGraphActionEnabled(context);
	}
}

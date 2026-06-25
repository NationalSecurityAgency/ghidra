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
package ghidra.app.plugin.core.debug.gui.variable;

import java.util.Objects;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.services.*;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo(
		shortDescription = "Variable Viewer For Traces",
		description = "Displays a table of variables at the current snap for a trace",
		category = PluginCategoryNames.DEBUGGER,
		packageName = DebuggerPluginPackage.NAME,
		status = PluginStatus.UNSTABLE,
		servicesRequired = { DebuggerStaticMappingService.class, DebuggerListingService.class,
				ProgressService.class, DebuggerControlService.class },
		eventsConsumed = { TraceActivatedPluginEvent.class }
)
public class DebuggerVariableViewerPlugin extends AbstractDebuggerPlugin {
	DebuggerVariableViewerProvider provider;

	public DebuggerVariableViewerPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		provider = new DebuggerVariableViewerProvider(this);
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (Objects.requireNonNull(event) instanceof TraceActivatedPluginEvent evt) {
			DebuggerCoordinates current = evt.getActiveCoordinates();
			provider.setCoordinates(current);
		}
	}

	@Override
	protected void dispose() {
		tool.removeComponentProvider(provider);
		super.dispose();
	}
}

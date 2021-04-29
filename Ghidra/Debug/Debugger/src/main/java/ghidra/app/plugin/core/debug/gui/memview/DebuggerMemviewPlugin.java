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
package ghidra.app.plugin.core.debug.gui.memview;

import java.util.List;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

@PluginInfo( //
		shortDescription = "Displays memory vs time", //
		description = "Provides visualiztion/navigation across time/address axes", //
		category = PluginCategoryNames.DEBUGGER, //
		packageName = DebuggerPluginPackage.NAME, //
		status = PluginStatus.RELEASED, //
		eventsConsumed = { //
			TraceActivatedPluginEvent.class //
		}, //
		servicesRequired = { //
			DebuggerTraceManagerService.class //
		}, //
		servicesProvided = { //
			MemviewService.class //
		} //
)
public class DebuggerMemviewPlugin extends AbstractDebuggerPlugin implements MemviewService {

	protected MemviewProvider provider;
	private DebuggerMemviewTraceListener listener;

	public DebuggerMemviewPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		provider = new MemviewProvider(getTool(), this);
		listener = new DebuggerMemviewTraceListener(provider);
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
		if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent ev = (TraceActivatedPluginEvent) event;
			listener.coordinatesActivated(ev.getActiveCoordinates());
		}
	}

	public MemviewProvider getProvider() {
		return provider;
	}

	public void toggleTrackTrace() {
		listener.toggleTrackTrace();
	}

	@Override
	public void setBoxes(List<MemoryBox> boxList) {
		provider.setBoxes(boxList);
	}

	@Override
	public void initViews() {
		provider.initViews();
	}

	@Override
	public void setProgram(Program program) {
		provider.setProgram(program);
	}
}

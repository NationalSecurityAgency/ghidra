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
package ghidra.app.plugin.core.debug.gui.model;

import java.util.*;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.gui.MultiProviderSaveBehavior;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.trace.model.Trace;

@PluginInfo(
	shortDescription = "Debugger model browser",
	description = "GUI to browse objects recorded to the trace",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.STABLE,
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
		TraceClosedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerTraceManagerService.class,
	})
public class DebuggerModelPlugin extends Plugin {

	private final class ForModelMultiProviderSaveBehavior
			extends MultiProviderSaveBehavior<DebuggerModelProvider> {
		@Override
		protected DebuggerModelProvider getConnectedProvider() {
			return connectedProvider;
		}

		@Override
		protected List<DebuggerModelProvider> getDisconnectedProviders() {
			return disconnectedProviders;
		}

		@Override
		protected DebuggerModelProvider createDisconnectedProvider() {
			return DebuggerModelPlugin.this.createDisconnectedProvider();
		}

		@Override
		protected void removeDisconnectedProvider(DebuggerModelProvider p) {
			p.removeFromTool();
		}
	}

	private DebuggerModelProvider connectedProvider;
	private final List<DebuggerModelProvider> disconnectedProviders = new ArrayList<>();
	private final ForModelMultiProviderSaveBehavior saveBehavior =
		new ForModelMultiProviderSaveBehavior();

	public DebuggerModelPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		this.connectedProvider = newProvider(false);
		super.init();
	}

	@Override
	protected void dispose() {
		tool.removeComponentProvider(connectedProvider);
		synchronized (disconnectedProviders) {
			for (DebuggerModelProvider p : disconnectedProviders) {
				tool.removeComponentProvider(p);
			}
		}
		super.dispose();
	}

	protected DebuggerModelProvider newProvider(boolean isClone) {
		return new DebuggerModelProvider(this, isClone);
	}

	protected DebuggerModelProvider createDisconnectedProvider() {
		DebuggerModelProvider p = newProvider(true);
		synchronized (disconnectedProviders) {
			disconnectedProviders.add(p);
		}
		return p;
	}

	public DebuggerModelProvider getConnectedProvider() {
		return connectedProvider;
	}

	public List<DebuggerModelProvider> getDisconnectedProviders() {
		return Collections.unmodifiableList(disconnectedProviders);
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent ev = (TraceActivatedPluginEvent) event;
			connectedProvider.coordinatesActivated(ev.getActiveCoordinates());
		}
		if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent ev = (TraceClosedPluginEvent) event;
			traceClosed(ev.getTrace());
		}
	}

	private void traceClosed(Trace trace) {
		connectedProvider.traceClosed(trace);
		synchronized (disconnectedProviders) {
			for (DebuggerModelProvider p : disconnectedProviders) {
				p.traceClosed(trace);
			}
		}
	}

	void providerRemoved(DebuggerModelProvider p) {
		synchronized (disconnectedProviders) {
			disconnectedProviders.remove(p);
		}
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		saveBehavior.writeConfigState(saveState);
	}

	@Override
	public void readConfigState(SaveState saveState) {
		saveBehavior.readConfigState(saveState);
	}

	@Override
	public void writeDataState(SaveState saveState) {
		saveBehavior.writeDataState(saveState);
	}

	@Override
	public void readDataState(SaveState saveState) {
		saveBehavior.readDataState(saveState);
	}
}

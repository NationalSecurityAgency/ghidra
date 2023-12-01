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
package ghidra.app.plugin.core.debug.service.progress;

import java.util.*;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.services.ProgressService;
import ghidra.debug.api.progress.*;
import ghidra.debug.api.progress.ProgressListener.Disposal;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.datastruct.ListenerSet;

@PluginInfo(
	category = PluginCategoryNames.MISC,
	shortDescription = "Service for monitoring task progress",
	description = """
			Implements a pub-sub model for notifying of tasks and progress. Publishers can create
			task monitors and update them using the TaskMonitor interface. Subscribers (there ought
			to only be one) are notified of the tasks and render progress in a component provider.
			""",
	servicesProvided = { ProgressService.class },
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.STABLE)
public class ProgressServicePlugin extends Plugin implements ProgressService {
	ListenerSet<ProgressListener> listeners = new ListenerSet<>(ProgressListener.class, true);

	Set<MonitorReceiver> monitors = new HashSet<>();

	public ProgressServicePlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public CloseableTaskMonitor publishTask() {
		DefaultCloseableTaskMonitor monitor = new DefaultCloseableTaskMonitor(this);
		synchronized (monitors) {
			monitors.add(monitor.getReceiver());
		}
		listeners.invoke().monitorCreated(monitor.getReceiver());
		return monitor;
	}

	@Override
	public Collection<MonitorReceiver> getAllMonitors() {
		synchronized (monitors) {
			return Set.copyOf(monitors);
		}
	}

	@Override
	public void addProgressListener(ProgressListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeProgressListener(ProgressListener listener) {
		listeners.remove(listener);
	}

	void disposeMonitor(DefaultMonitorReceiver monitor, Disposal disposal) {
		boolean changed;
		synchronized (monitors) {
			changed = monitors.remove(monitor);
		}
		if (changed) {
			listeners.invoke().monitorDisposed(monitor, disposal);
		}
	}
}

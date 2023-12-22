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
package ghidra.app.plugin.core.debug.service.target;

import java.util.*;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.services.DebuggerTargetService;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.TargetPublicationListener;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.trace.model.Trace;
import ghidra.util.datastruct.ListenerSet;

@PluginInfo(shortDescription = "Debugger targets manager service", description = "Maintains a collection of published targets and notifies listeners of changes.", category = PluginCategoryNames.DEBUGGER, packageName = DebuggerPluginPackage.NAME, status = PluginStatus.RELEASED, servicesProvided = {
	DebuggerTargetService.class, })
public class DebuggerTargetServicePlugin extends Plugin implements DebuggerTargetService {

	public DebuggerTargetServicePlugin(PluginTool tool) {
		super(tool);
	}

	private final Map<Trace, Target> targets = new HashMap<>();
	private final ListenerSet<TargetPublicationListener> listeners =
		new ListenerSet<>(TargetPublicationListener.class, true);

	@Override
	public void publishTarget(Target target) {
		boolean notify;
		synchronized (targets) {
			notify = targets.put(target.getTrace(), target) != target;
		}
		if (notify) {
			listeners.invoke().targetPublished(target);
		}
	}

	@Override
	public void withdrawTarget(Target target) {
		boolean notify;
		synchronized (targets) {
			notify = targets.remove(target.getTrace()) == target;
		}
		if (notify) {
			listeners.invoke().targetWithdrawn(target);
		}
	}

	@Override
	public List<Target> getPublishedTargets() {
		synchronized (targets) {
			return List.copyOf(targets.values());
		}
	}

	@Override
	public Target getTarget(Trace trace) {
		synchronized (targets) {
			return targets.get(trace);
		}
	}

	@Override
	public void addTargetPublicationListener(TargetPublicationListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeTargetPublicationListener(TargetPublicationListener listener) {
		listeners.remove(listener);
	}
}

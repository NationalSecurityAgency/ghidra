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
package ghidra.app.plugin.core.debug.service.workflow;

import java.util.*;
import java.util.function.Function;

import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.Trace;

public class MultiToolTraceListenerManager<L extends AbstractMultiToolTraceListener> {
	private final Function<Trace, L> listenerFactory;
	private final Map<Trace, L> listenersByTrace = new HashMap<>();

	public MultiToolTraceListenerManager(Function<Trace, L> listenerFactory) {
		this.listenerFactory = listenerFactory;
	}

	public synchronized void enable(DebuggerWorkflowServicePlugin wp) {
		for (PluginTool tool : wp.getProxyingPluginTools()) {
			DebuggerTraceManagerService traceManager =
				tool.getService(DebuggerTraceManagerService.class);
			if (traceManager == null) {
				continue;
			}
			for (Trace trace : traceManager.getOpenTraces()) {
				L listener = listenersByTrace.computeIfAbsent(trace, t -> {
					L l = listenerFactory.apply(t);
					l.init();
					return l;
				});
				listener.openedBy(tool);
			}
		}
	}

	public synchronized void disable() {
		for (Iterator<L> it = listenersByTrace.values().iterator(); it.hasNext();) {
			L listener = it.next();
			listener.dispose();
			it.remove();
		}
	}

	public synchronized void traceOpened(PluginTool tool, Trace trace) {
		L listener = listenersByTrace.computeIfAbsent(trace, t -> {
			L l = listenerFactory.apply(t);
			l.init();
			return l;
		});
		listener.openedBy(tool);
	}

	public synchronized void traceClosed(PluginTool tool, Trace trace) {
		if (listenersByTrace.get(trace).closedBy(tool)) {
			listenersByTrace.remove(trace).dispose();
		}
	}
}

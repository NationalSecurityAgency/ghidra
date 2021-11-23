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
package ghidra.app.plugin.core.debug.workflow;

import java.util.*;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.app.plugin.core.debug.service.workflow.*;
import ghidra.app.services.*;
import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.util.TraceChangeType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractMapDebuggerBot implements DebuggerBot {
	protected class ForChangesTraceListener extends AbstractMultiToolTraceListener {
		public ForChangesTraceListener(Trace trace) {
			super(trace);

			for (TraceChangeType<?, ?> type : getChangeTypes()) {
				listenFor(type, this::changed);
			}
		}

		private void changed() {
			queueTrace(trace);
		}
	}

	protected abstract Collection<TraceChangeType<?, ?>> getChangeTypes();

	private DebuggerWorkflowServicePlugin plugin;

	private final MultiToolTraceListenerManager<ForChangesTraceListener> listeners =
		new MultiToolTraceListenerManager<>(ForChangesTraceListener::new);

	private final Set<Trace> traceQueue = new HashSet<>();
	// Debounce to ensure we don't get too eager if manager is still opening stuff
	private final AsyncDebouncer<Void> debouncer =
		new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, 500);
	{
		debouncer.addListener(this::queueSettled);
	}

	@Override
	public void enable(DebuggerWorkflowServicePlugin wp) {
		this.plugin = wp;

		listeners.enable(wp);
		for (PluginTool t : plugin.getProxyingPluginTools()) {
			DebuggerTraceManagerService traceManager =
				t.getService(DebuggerTraceManagerService.class);
			if (traceManager == null) {
				continue;
			}
			queueTraces(traceManager.getOpenTraces());
		}
	}

	@Override
	public void disable() {
		plugin = null;

		listeners.disable();
	}

	@Override
	public boolean isEnabled() {
		return plugin != null;
	}

	@Override
	public void traceOpened(PluginTool tool, Trace trace) {
		listeners.traceOpened(tool, trace);
		queueTrace(trace);
	}

	@Override
	public void traceClosed(PluginTool tool, Trace trace) {
		listeners.traceClosed(tool, trace);
	}

	@Override
	public void programOpened(PluginTool t, Program program) {
		DebuggerTraceManagerService traceManager = t.getService(DebuggerTraceManagerService.class);
		if (traceManager == null) {
			return;
		}
		queueTraces(traceManager.getOpenTraces());
	}

	private void queueTrace(Trace trace) {
		synchronized (traceQueue) {
			traceQueue.add(trace);
		}
		debouncer.contact(null);
	}

	private void queueTraces(Collection<Trace> traces) {
		synchronized (traceQueue) {
			traceQueue.addAll(traces);
		}
		debouncer.contact(null);
	}

	private void queueSettled(Void __) {
		Set<Trace> traces;
		synchronized (traceQueue) {
			traces = Set.copyOf(traceQueue);
			traceQueue.clear();
		}

		Map<Trace, Pair<PluginTool, Set<Program>>> toAnalyze = new HashMap<>();
		for (Trace trace : traces) {
			for (PluginTool tool : plugin.getProxyingPluginTools()) {
				DebuggerTraceManagerService traceManager =
					tool.getService(DebuggerTraceManagerService.class);
				if (traceManager == null) {
					continue;
				}
				ProgramManager programManager = tool.getService(ProgramManager.class);
				if (programManager == null) {
					continue;
				}
				if (!traceManager.getOpenTraces().contains(trace)) {
					continue;
				}
				Pair<PluginTool, Set<Program>> programs =
					toAnalyze.computeIfAbsent(trace, t -> Pair.of(tool, new HashSet<>()));
				programs.getRight().addAll(List.of(programManager.getAllOpenPrograms()));
			}
		}

		for (Map.Entry<Trace, Pair<PluginTool, Set<Program>>> ent : toAnalyze.entrySet()) {
			PluginTool tool = ent.getValue().getLeft();
			Trace trace = ent.getKey();
			Set<Program> programs = ent.getValue().getRight();
			analyzeTrace(tool, trace, programs);
		}
	}

	private void analyzeTrace(PluginTool tool, Trace trace, Set<Program> programs) {
		BackgroundCommand cmd = new BackgroundCommand(getDescription(), true, true, false) {
			@Override
			public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
				try {
					doAnalysis(tool, trace, programs, monitor);
					return true;
				}
				catch (CancelledException e) {
					return false;
				}
			}
		};
		tool.executeBackgroundCommand(cmd, trace);
	}

	protected abstract void doAnalysis(PluginTool tool, Trace trace, Set<Program> programs,
			TaskMonitor monitor) throws CancelledException;
}
